#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/kdev_t.h>

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <typeinfo>


#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#include "oci-decorator.h"

static const std::string oci_decorator_conf = "/etc/oci-decorator/oci-decorator.d/";

static int32_t log_level=LOG_DEBUG;

#define pr_perror(fmt, ...)   syslog(LOG_ERR,     "onload-hook <error>:   " fmt ": %m\n", ##__VA_ARGS__)
#define pr_pinfo(fmt, ...)    syslog(LOG_INFO,    "onload-hook <info>:    " fmt "\n", ##__VA_ARGS__)
#define pr_pwarning(fmt, ...) syslog(LOG_WARNING, "onload-hook <warning>: " fmt "\n", ##__VA_ARGS__)
#define pr_pdebug(fmt, ...)   syslog(LOG_DEBUG,   "onload-hook <debug> %d :  " fmt "\n", __LINE__,  ##__VA_ARGS__)


using namespace std;
namespace rd = ::rapidjson;

fstream lg;

void read_directory(const string & name, vector<string> & v)
{
        DIR* dirp = opendir(name.c_str());
        struct dirent * dp;
        while ((dp = readdir(dirp)) != NULL) {
                v.push_back(dp->d_name);
        }
        closedir(dirp);
}

static int32_t cp(const string & dst, const string & src)
{
        ifstream f_src(src.c_str(), ios::binary);
        ofstream f_dst(dst.c_str(), ios::binary);

        f_dst << f_src.rdbuf();
}

static int32_t zcopy(const string & dst, const string & src, const string & rootfs)
{
        const string file_dst = rootfs + dst;
        
        pr_pdebug("Copying %s file to: %s", dst.c_str(), file_dst.c_str());
        if (cp(file_dst, src) == -1) {
                pr_perror("Failed to copy file src=%s dst=%s", src.c_str(), file_dst.c_str());
                return 0;
        }


	return 0;
}

static int32_t zmkdir(const string & dst, const string & rootfs)
{
        
        const string file_dst = rootfs + dst;
        struct stat stat_struct;
	
	
	if (stat(file_dst.c_str(), &stat_struct) == 0 && S_ISDIR(stat_struct.st_mode)) {
		pr_pdebug("Directory exists, skipping: %s", file_dst.c_str());
	} else {
		pr_pdebug("Creating directory: %s", file_dst.c_str());
		if (mkdir(file_dst.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == -1) {
			pr_perror("Failed to create directory: %s", file_dst.c_str());
			return 0;
		}
	}
	
	return 0;
}

static int32_t zmknod(const string & dev, const int32_t major, const int32_t minor, const string & rootfs)
{
        const string file_dst = rootfs + dev;
        
	struct stat stat_struct;
        
	dev_t mdev = makedev(major, minor);
	
	if (stat(file_dst.c_str(), &stat_struct) == 0) {
		pr_pdebug("Device exists, skipping: %s", file_dst.c_str());
	} else {
		pr_pdebug("Creating device file: %s", file_dst.c_str());
		if (mknod(file_dst.c_str(), S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, mdev) == -1) {
			pr_perror("%s: Failed to create device file %s", dev.c_str());
			return 0;
		}
	}

	return 0;
}

static int32_t zchmod(const string & path, const mode_t mode, const string & rootfs)
{
        const string file_dst = rootfs + path;
	chmod(file_dst.c_str(), mode);
}

static bool get_major_minor_from_proc(const string & device, int32_t & major, int32_t & minor)
{
        string line;
        ifstream pd("/proc/devices");

        while (getline(pd, line)) {

                size_t found = line.find(device);
                
                if (found != string::npos) {
                        istringstream iss(line);
                        vector<string> results((istream_iterator<string>(iss)),
                                               istream_iterator<string>());
                        /* skip if the device is a prefix of another device */
                        if (device.size() != results[1].size()) {
                                continue;
                        }

                        major = stoi(results[0]);
                        minor = 0;
                }
        }
        return true;
}

static bool get_major_minor_from_dev(const string & device, int32_t & major, int32_t & minor)
{
        struct stat stat_;
        string file = "/dev/" + device; 
        
        assert(stat(file.c_str(), &stat_) == 0);

        major = MAJOR(stat_.st_rdev);
        minor = MINOR(stat_.st_rdev);

        return true;
}

static bool get_major_minor(string device, int32_t & major, int32_t & minor)
{
        string line;

        get_major_minor_from_proc(device, major, minor);

        if (major != -1 && major > 0) { return true; }

        get_major_minor_from_dev(device, major, minor);

        assert(major != -1 && major > 0);
        assert(minor != -1);
                
        return true;
}


static string get_device_cgroup(const int32_t pid)
{
        string line;
        stringstream proc_pid_cgroup;

        proc_pid_cgroup << "/proc/" << pid << "/cgroup";
        
        ifstream ppc(proc_pid_cgroup.str().c_str());

        while (getline(ppc, line)) {
                
                size_t found = line.find("devices");

                if (found != string::npos) {
                        string token;
                        stringstream iss(line);
                        vector<string> cgroup;
                        
                        while (getline(iss, token, ':')) { cgroup.push_back(token); }

                        return cgroup[2];
                }
        }
        return string();
}

static int32_t zexec(string cmd, string & out)
{
        cmd.append(" 2>&1");
        FILE* file = popen(cmd.c_str(), "r");
        assert(file);

        char line[1024];
        while (fgets(line, 1024, file)) {
                out.append(line);
                out.append("\n");
        };
        return pclose(file);
}

static bool join_pid_namespace(const int32_t pid)
{
        int32_t fd = -1;
        string pidns = "/proc/" + to_string(pid) + "/ns/mnt";

        fd = open(pidns.c_str(), O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open mnt namespace fd %s", pidns.c_str());
		return false;
	}
	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_perror("Failed to setns to %s", pidns.c_str());
		return false;
	}
        close(fd);
        
        return true;
}

static bool prepare_container(const int32_t pid, string & device_cgroup)
{
        assert(join_pid_namespace(pid));
        device_cgroup = get_device_cgroup(pid);
        assert(device_cgroup.size() > 0);
}

static bool prestart_devices(const string & rootfs, const string & cgroup, vector<string> devices)
{
        for (auto & dev : devices) {
                lg << dev << endl;
                string path = "/dev/" + dev;
                int32_t major = -1;
                int32_t minor = -1;
                
                get_major_minor(dev, major, minor);

                zmknod(path, major, minor, rootfs);
                stringstream allow;
                allow << "cgset -r \"devices.allow=c " << major << ":" << minor << " rwm\" " << cgroup;

                string out; 
                assert(zexec(allow.str(), out) == 0);
        }
        return true;
}
static bool prestart_binaries(const string & rootfs, vector<string> binaries)
{
        for (auto & bin : binaries) {
                lg << bin << endl;
                zcopy(bin, bin, rootfs);
                zchmod(bin,  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, rootfs);
        }
        return true;
}

static bool prestart_directories(const string & rootfs, vector<string> directories)
{
        for (auto & dir : directories) {
                lg << dir << endl;
                zmkdir(dir, rootfs);
        }

        return true;
}
static bool prestart_libraries(const string & rootfs, vector<string> libraries)
{
        for (auto & lib : libraries) {
                lg << lib << endl;
                zcopy(lib, lib, rootfs);
        }

        string ldconfig = "PATH=/usr/sbin:/usr/bin:/bin:/sbin chroot ";
        ldconfig.append(rootfs);
        ldconfig.append(" ldconfig");

        string out; 
        assert(zexec(ldconfig, out) == 0);

        return true;
}
static bool prestart_miscellaneous(const string & rootfs, vector<string> miscellaneous)
{
        for (auto & msc : miscellaneous) {
                lg << msc << endl;
                zcopy(msc, msc, rootfs);
        }
        return true;
}
        
static bool prestart(const string & rootfs, const string & cgroup,
                     const oci_config_ & cfg)
{
        for (int32_t i = 0; i < cfg.driver_feature.size(); i++) {

                auto & curr = cfg.inventory[i];

                prestart_devices(rootfs, cgroup, curr[inventory::devices]);
                prestart_directories(rootfs, curr[inventory::directories]);
                prestart_binaries(rootfs, curr[inventory::binaries]);
                prestart_libraries(rootfs, curr[inventory::libraries]);
                prestart_miscellaneous(rootfs, curr[inventory::miscellaneous]);
                                  
        }

	return true;
}

/*
 * Read the entire content of stream pointed to by 'from' into a buffer in memory.
 * Return the complete json string.
 */

static string get_json_string(std::istream& from)
{
        string json_string;
        string input_line;

        while(!from.eof()) {
                getline(from, input_line);
                json_string.append(input_line);
        }
        return json_string;
}

static bool get_config_from_bundle(string & bundle, string & config)
{
        bundle.append("/config.json");
        fstream from_bundle(bundle.c_str(), fstream::in);
        config = get_json_string(from_bundle);

        return true;
}

static bool get_rootfs_from_config(const string & config, string & rootfs, const string & bundle)
{
        rd::Document doc;
        doc.Parse(config.c_str());
        
        assert(doc.HasMember("root"));

        rd::Value & root = doc["root"];

        assert(root.HasMember("path"));
        assert(root["path"].IsString());
        
        string rootfs_ = root["path"].GetString();

        if (rootfs_.compare(0,1,"/") == 0) {
                rootfs = rootfs_;
        } else {
                rootfs.append(bundle).append("/").append(rootfs_);
        }
        
	return true;
}

static bool get_info_from_state(string & id, int32_t & pid, string & bundle)
{
	/* Read the entire state from stdin: 
         * ociVersion, id, pid, root, bundlePath */
	string state = get_json_string(std::cin);

        rd::Document doc;
        doc.Parse(state.c_str());

        assert(doc.HasMember("id"));
        assert(doc["id"].IsString());

        assert(doc.HasMember("pid"));
        assert(doc["pid"].IsInt());

        id  = doc["id"].GetString();
        pid = doc["pid"].GetInt();

        assert(doc.HasMember("bundlePath"));
        assert(doc["bundlePath"].IsString());

        bundle = doc["bundlePath"].GetString();

        return true;
}
static bool activation_flag_in_env(const string & config,
                                   const vector<oci_config_> & oci_config)
{
      rd::Document doc;
      doc.Parse(config.c_str());

      assert(doc.HasMember("process"));

      rd::Value & pro = doc["process"];

      assert(pro.HasMember("env"));
      assert(pro["env"].IsArray());

      rd::Value & env = pro["env"];
      
      for (size_t e = 0; e < env.Size(); e++) {
              string flag = env[e].GetString();
              for (auto & o : oci_config) {
                      size_t found = flag.find(o.activation_flag);
                      if (found != string::npos) {
                              lg << "TRUE" << endl;
                              return true;
                      }
              }
      }
      return false;
}

static bool parse_driver_feature(rd::Value & doc, oci_config_ & oci_config)
{
        assert(doc.HasMember("driver_feature"));
        assert(doc["driver_feature"].IsArray());

        rd::Value & df = doc["driver_feature"];

        for (size_t i = 0; i < df.Size(); i++) {
                oci_config.driver_feature.push_back(df[i].GetString());
        }
        return true;
}

static bool parse_activation_flag(rd::Value & doc, oci_config_ & oci_config)
{
        assert(doc.HasMember("activation_flag"));
        assert(doc["activation_flag"].IsString());

        oci_config.activation_flag = doc["activation_flag"].GetString();
}

static bool parse_feature_entry(rd::Value & doc, const string & item, vector<string> & entry)
{
        if(doc.HasMember(item.c_str())) {
                rd::Value & arr = doc[item.c_str()];
                assert(arr.IsArray());
                for (size_t i = 0; i < arr.Size(); i++)
                {
                        entry.push_back(arr[i].GetString());
                }
        }
        return true;
}

static bool parse_inventory(rd::Value & doc, oci_config_ & cfg)
{
        for (int32_t i = 0; i < cfg.driver_feature.size(); i++) {
                string name = cfg.driver_feature[i];
                
                assert(doc.HasMember(name.c_str()));
                rd::Value & ftr = doc[name.c_str()];
                
                cfg.inventory.resize(cfg.driver_feature.size());
                cfg.inventory[i].resize(inventory::group_entries);

                auto & curr = cfg.inventory[i];

                assert(parse_feature_entry(ftr, "devices", curr[inventory::devices]));
                assert(parse_feature_entry(ftr, "binaries", curr[inventory::binaries]));
                assert(parse_feature_entry(ftr, "libraries", curr[inventory::libraries]));
                assert(parse_feature_entry(ftr, "directories", curr[inventory::directories]));
                assert(parse_feature_entry(ftr, "miscellaneous", curr[inventory::miscellaneous]));
        }
        return true;
}

static bool get_oci_config_definitions(vector<oci_config_> & cfg)
{
        vector<string> configs;
        read_directory(oci_decorator_conf, configs);
        
        for (auto & file : configs) {
                if (file.compare(".") == 0 || file.compare("..") == 0) { continue; }

                
                file.insert(0, oci_decorator_conf);
                fstream f(file.c_str(), fstream::in);
                string json = get_json_string(f);

                rd::Document doc;
                rd::ParseResult res = doc.Parse(json.c_str());
                if (!res) {
                        auto err =  GetParseError_En(res.Code());
                        lg << err << endl;
                        pr_pdebug("%s", err);
                }
                assert(res);
        
                cfg.push_back(oci_config_());
                auto & curr = cfg.back();
 
                assert(parse_activation_flag(doc, curr));
                assert(parse_driver_feature(doc, curr));
                
                assert(doc.HasMember("inventory"));
                rd::Value & inv = doc["inventory"];

                assert(parse_inventory(inv, curr));
        }
        return true;
}


int32_t main(int32_t argc, char *argv[])
{
        lg.open("/tmp/oci-log.txt", std::fstream::in | std::fstream::out | std::fstream::app);
        
        string id;
        int32_t pid;
        string bundle;
        string json_config;

        assert(setlogmask(LOG_UPTO(log_level)));
        assert(get_info_from_state(id, pid, bundle));
        assert(get_config_from_bundle(bundle, json_config));

        vector<oci_config_> oci_config;
        assert(get_oci_config_definitions(oci_config));
        
        if (!activation_flag_in_env(json_config, oci_config))
        {
                pr_pdebug("prestart not run for this container, check activation flags and set your environment");
                return EXIT_SUCCESS;
        }
        
        /* OCI hooks set target_pid to 0 on poststop, as the container process
         * already exited.  If target_pid is bigger than 0 then it is a start
         * hook.
         * In most cases the calling program should set the environment variable "stage"
         * like prestart, poststart or poststop.
         * We also support passing the stage as argv[1],
         * In certain cases we also support passing of no argv[1], and no environment variable,
         * then default to prestart if the target_pid != 0, poststop if target_pid == 0. */
	char *stage = getenv("stage");
        
	if (stage == NULL && argc > 2) {
		stage = argv[1];
	}
        
	if ((stage != NULL && !strcmp(stage, "prestart")) || (argc == 1 && pid)) {

                string rootfs;
		assert(get_rootfs_from_config(json_config, rootfs, bundle));

                string device_cgroup;
                assert(prepare_container(pid, device_cgroup));
                pr_pdebug("prestart container_id:%s rootfs:%s", id.c_str(), rootfs.c_str());
                
                for (int32_t i = 0; i < oci_config.size(); i++) {
                        assert(prestart(rootfs, device_cgroup, oci_config[i]));
                }
        
	} else {
		pr_pdebug("%s: only runs in prestart stage, ignoring", id.c_str());
	}
  
	return EXIT_SUCCESS;
}
