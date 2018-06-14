
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <yajl/yajl_tree.h>
#include <ctype.h>

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>

#include <sys/types.h>
#include <dirent.h>

#include <libconfig.h++>

#include <rapidjson/document.h>

#include "oci-decorator.h"


#define _cleanup_(x) __attribute__((cleanup(x)))


static const std::string oci_decorator_conf = "/etc/oci-decorator/oci-decorator.d/";

static int32_t log_level=LOG_DEBUG;

static inline void closep(int32_t *fd) {
	if (*fd >= 0) {	close(*fd); }
	*fd = -1;
}

static inline void fclosep(FILE **fp) {
	if (*fp) { fclose(*fp); }
	*fp = NULL;
}

static inline void closedirp(DIR **dir) {
	if (*dir) { closedir(*dir); }
	*dir = NULL;
}

#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_dir_ _cleanup_(closedirp)
#define _cleanup_fclose_ _cleanup_(fclosep)

#define DEFINE_CLEANUP_FUNC(type, func)	      \
	static inline void func##p(type *p) { \
		if (*p)                       \
			func(*p);             \
 	}                                     \

DEFINE_CLEANUP_FUNC(yajl_val, yajl_tree_free)

#define pr_perror(fmt, ...)   syslog(LOG_ERR,     "onload-hook <error>:   " fmt ": %m\n", ##__VA_ARGS__)
#define pr_pinfo(fmt, ...)    syslog(LOG_INFO,    "onload-hook <info>:    " fmt "\n", ##__VA_ARGS__)
#define pr_pwarning(fmt, ...) syslog(LOG_WARNING, "onload-hook <warning>: " fmt "\n", ##__VA_ARGS__)
#define pr_pdebug(fmt, ...)   syslog(LOG_DEBUG,    "onload-hook <debug> %d :  " fmt "\n", __LINE__,  ##__VA_ARGS__)

#define BUFLEN 1024
#define CHUNKSIZE 4096

using namespace std;
using namespace libconfig;

namespace rd = ::rapidjson;

fstream lg;


string shortid(const string & id)
{
	return id.substr(0, 12);
}

void read_directory(const string & name, vector<string> & v)
{
        DIR* dirp = opendir(name.c_str());
        struct dirent * dp;
        while ((dp = readdir(dirp)) != NULL) {
                v.push_back(dp->d_name);
        }
        closedir(dirp);
}

long GetFileSize(std::string filename)
{
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
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

static int32_t get_major_num(string device)
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
                        
                        pr_pdebug("major %s device %s", results[0].c_str(), results[1].c_str());
                        return stoi(results[0]);
                }
                        

        }
        return -1;
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
   
}



static int32_t prestart(const string & id,
                        const string & rootfs,
                        int32_t pid)
{
	pr_pdebug("prestart container_id:%s rootfs:%s", id.c_str(), rootfs.c_str());
        
        _cleanup_close_  int32_t fd = -1;

        stringstream  proc_ns_mnt;
        proc_ns_mnt << "/proc/" << pid << "/ns/mnt";
        
        fd = open(proc_ns_mnt.str().c_str(), O_RDONLY);
	if (fd < 0) {
		pr_perror("%s: Failed to open mnt namespace fd %s", id.c_str(), proc_ns_mnt.str().c_str());
		return EXIT_FAILURE;
	}
	/* Join the mount namespace of the target process */
	if (setns(fd, 0) == -1) {
		pr_perror("%s: Failed to setns to %s", id.c_str(), proc_ns_mnt.str().c_str());
		return EXIT_FAILURE;
	}

  
        enum inventory {
                devices = 0,
                binaries,
                directories,
                libraries,
                miscellaneous,
                group_entries
        };

        string inventory_name[group_entries] = {
                "devices",
                "binaries",
                "directories",
                "libraries",
                "miscellaneous"
        };
         
        vector<vector<string>> _cfg(group_entries);
        
        vector<string>  conf_files;
        read_directory(oci_decorator_conf, conf_files);
                        
        Config cfg;        
        for (auto & file : conf_files) {
                if (file.compare(".") != 0 && file.compare("..") != 0) {

                        cfg.readFile((oci_decorator_conf + file).c_str());
                        string name = cfg.lookup("name");
                        
                        const Setting& root = cfg.getRoot();

                        for (int32_t inv = 0; inv < group_entries; inv++) {
                                
                                const Setting& entry = root["inventory"][inventory_name[inv]];
                                for (int32_t i = 0; i < entry.getLength(); i++)  {
                                        _cfg[inv].push_back(entry[i]);
                                }       
                        }
                }
        }

        
        string device_cgroup = get_device_cgroup(pid);
        pr_pdebug("cgroup: %s", device_cgroup.c_str());

        for (auto & dev : _cfg[devices]) {
                string dev_path = "/dev/" + dev;
                int32_t major = get_major_num(dev);
                
                zmknod(dev_path, major, 0, rootfs);

                stringstream allow_device;
                allow_device << "cgset -r \"devices.allow=c " << major << ":0 rwm\" " << device_cgroup;
                system(allow_device.str().c_str());
                pr_pdebug("%s", allow_device.str().c_str());
        }
        
        for (auto & dir : _cfg[directories]) {
                zmkdir(dir, rootfs);
        }
        
        for (auto & bin : _cfg[binaries]) {
                zcopy(bin, bin, rootfs);
                zchmod(bin,  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, rootfs);
        }
        for (auto & msc : _cfg[miscellaneous]) {
                zcopy(msc, msc, rootfs);
        }

        for (auto & lib : _cfg[libraries]) {
                zcopy(lib, lib, rootfs);
        }


        
	return 0;
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
static bool activation_flag_in_env(const string & config)
{
      rd::Document doc;
      doc.Parse(config.c_str());

      assert(doc.HasMember("process"));

      rd::Value & pro = doc["process"];

      assert(pro.HasMember("env"));
      assert(pro["env"].IsArray());

      rd::Value & env = pro["env"];
      
      for (size_t e = 0; e < env.Size(); e++) 
              lg << env[e].GetString() << endl;
      
      

      return true;
}

struct oci_config {
        string version;
        string log_level;
        string activation_flag;
        vector<string> driver_feature;
        vector<vector<string>>  inventory;
};

int32_t main(int32_t argc, char *argv[])
{
        lg.open("/tmp/oci-log.txt", std::fstream::in | std::fstream::out | std::fstream::app);
        
        string id;
        int32_t pid;
        string bundle;
        string config;

        assert(setlogmask(LOG_UPTO(log_level)));
        assert(get_info_from_state(id, pid, bundle));
        assert(get_config_from_bundle(bundle, config));

        if (!activation_flag_in_env(config))
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
		assert(get_rootfs_from_config(config, rootfs, bundle));

        
/*		if (prestart(id, rootfs, pid) != 0) {
			return EXIT_FAILURE;
		}
*/              
	} else {
		pr_pdebug("%s: only runs in prestart stage, ignoring", id.c_str());
	}
  
	return EXIT_SUCCESS;
}
