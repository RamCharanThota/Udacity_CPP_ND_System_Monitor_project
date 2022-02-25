#include "linux_parser.h"

#include <bits/stdc++.h>
#include <dirent.h>
#include <unistd.h>

#include <sstream>
#include <string>
#include <vector>

using std::stof;
using std::string;
using std::to_string;
using std::vector;

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel() {
  string os, kernel, version;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// TODO: Read and return the system memory utilization
float LinuxParser::MemoryUtilization() {
  string line, key;
  float value;
  float mem_utilization = 0, mem_total = 0, mem_free = 0;
  std::ifstream stream(kProcDirectory + kMeminfoFilename);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "MemTotal") {
          mem_total = value;
        } else if (key == "MemFree") {
          mem_free = value;
        }
      }
      mem_utilization = (mem_total - mem_free) / mem_total;
    }
  }

  return mem_utilization;
}

// TODO: Read and return the system uptime
long LinuxParser::UpTime() {
  long up_time, idle_time;
  string line;
  std::ifstream stream(kProcDirectory + kUptimeFilename);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      linestream >> up_time >> idle_time;
    }
  }
  return up_time;
}

// TODO: Read and return the number of jiffies for the system
long LinuxParser::Jiffies() {
  long sys_uptime = LinuxParser::UpTime();
  long sys_frequency = sysconf(_SC_CLK_TCK);
  long total_jiffies = sys_uptime * sys_frequency;
  return total_jiffies;
}

// TODO: Read and return the number of active jiffies for a PID
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::ActiveJiffies(int pid [[maybe_unused]]) {
  string line;
  long active_jiff_sum = 0;
  long value_from_linestream = 0;
  std::ifstream stream(kProcDirectory + std::to_string(pid) + kStatFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    int index = 0;

    while (linestream) {
      linestream >> value_from_linestream;
      if (index == 13 || index == 16) {
        active_jiff_sum = active_jiff_sum + value_from_linestream;
      }

      ++index;
    }
  }

  return active_jiff_sum;
}

// TODO: Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() {
  string line;
  long active_jiff_sum = 0;
  long value_from_linestream = 0;
  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    int index = 0;

    while (linestream) {
      linestream >> value_from_linestream;
      if (index != 0) {
        active_jiff_sum = active_jiff_sum + value_from_linestream;
      }

      ++index;
    }
  }

  return active_jiff_sum;
}

// TODO: Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() {
  string line;
  long idle_jiff_sum = 0;
  long value_from_linestream = 0;
  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    int index = 0;

    while (linestream) {
      linestream >> value_from_linestream;
      if (index == 4 || index == 5) {
        idle_jiff_sum = idle_jiff_sum + value_from_linestream;
      }

      ++index;
    }
  }
  return idle_jiff_sum;
}

// TODO: Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization() {
  long uptime_of_system = LinuxParser::UpTime();
  vector<int> processes_pid_list = LinuxParser::Pids();
  vector<string> cpu_util_list;
  std::ifstream stream;
  for (int process_pid : processes_pid_list) {
    string line;
    string file_path = kProcDirectory +to_string(process_pid) + kStatFilename;
    stream.open(file_path);
    string token;
    long token_long = 0;
    long utime=0;
    long stime=0;
    long cutime=0;
    long cstime=0;
    long starttime=0;
    int clc_tck=sysconf(_SC_CLK_TCK);
    if (stream.is_open()) {
      std::getline(stream, line);
      std::istringstream linestream(line);
      int index = 0;

      while (linestream) {
        linestream >> token;
          if(index==13){
           utime=stol(token);
          }

          if(index==14){
           stime=stol(token);
          }

          if(index==15){
           cutime=stol(token);
          }

          if(index==16){
           cstime=stol(token);
          }

          if(index==21){
           starttime=stol(token);
           break;
          }

        ++index;
      }
      long total_time=utime+stime+cutime+cstime;
      long total_elapsed_time=uptime_of_system-(starttime/clc_tck);
      long cpu_usage=100*((total_time/clc_tck)/total_elapsed_time);
      cpu_util_list.push_back(to_string(cpu_usage));
    }
  }
  stream.close();
  return cpu_util_list;
}

// TODO: Read and return the total number of processes
int LinuxParser::TotalProcesses() {
  string line;
  int total_process = 0;
  std::string total_proc;
  string name = 0;
  // int index = 0;
  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      if (linestream) {
        linestream >> name >> total_proc;
        if (name == "processes:") {
          total_process = std::stoi(total_proc);
        }
      }
    }
  }

  return total_process;
}

// TODO: Read and return the number of running processes
int LinuxParser::RunningProcesses() {
  string line;
  int running_process = 0;
  std::string running_proc;
  string name = 0;

  std::ifstream stream(kProcDirectory + kStatFilename);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      if (linestream) {
        linestream >> name >> running_proc;
        if (name == "procs_running") {
          running_process = std::stoi(running_proc);
          break;
        }
      }
    }
  }
  return running_process;
}

// TODO: Read and return the command associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Command(int pid) {
  string line;
  string file_path = kProcDirectory + to_string(pid) + kCmdlineFilename;
  std::ifstream stream(file_path);
  if (stream.is_open()) {
    std::getline(stream, line);
  }

  return line;
}

// TODO: Read and return the memory used by a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Ram(int pid) {
  long kb_to_mb = 0.0009765625;  // 1kb is equal to 0.0009765625 mb
  string line, key, val1;
  string memory_used = NULL;
  string file_path = kProcDirectory + to_string(pid) + kStatusFilename;
  std::ifstream stream(file_path);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      if (linestream) {
        linestream >> key >> val1;
        if (key == "VmSize:") {
          memory_used = val1;
          break;
        }
      }
    }
  }

  memory_used = to_string(stol(memory_used) * 0.0009765625);

  return memory_used;
}

// TODO: Read and return the user ID associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Uid(int pid) {
  string line, key, val1;
  string uid;
  string file_path = kProcDirectory + to_string(pid) + kStatusFilename;
  std::ifstream stream(file_path);
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream linestream(line);
      if (linestream) {
        linestream >> key >> val1;
        if (key == "uid") {
          uid = val1;
          break;
        }
      }
    }
  }

  return uid;
}

// TODO: Read and return the user associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::User(int pid) {
  string line = NULL;
  string file_path = "/etc/passwd";
  std::ifstream stream(file_path);
  string word = NULL;
  string user_name = NULL;
  if (stream.is_open()) {
    while (std::getline(stream, line)) {
      std::istringstream ss(line);
      std::string token;
      bool read_user_name = false;

      while (std::getline(ss, token, ':')) {
        if (!read_user_name) {
          user_name = token;
          read_user_name = true;
        }
        if (token == to_string(pid)) {
          return user_name;
        }
      }
    }
  }
  return user_name;
}

// TODO: Read and return the uptime of a process
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::UpTime(int pid) {
  string line;
  string file_path = kProcDirectory + to_string(pid) + kStatFilename;
  std::ifstream stream(file_path);
  string up_time = NULL;
  long up_time_long = 0;
  long up_time_in_sec = 0;
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    int index = 0;

    while (linestream) {
      linestream >> up_time;
      if (index == 21) {
        up_time_long = stol(up_time);
        up_time_in_sec = up_time_long / sysconf(_SC_CLK_TCK);

        return up_time_in_sec;
      }

      ++index;
    }
  }

  return up_time_in_sec;
}
