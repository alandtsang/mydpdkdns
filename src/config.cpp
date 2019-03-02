// Read an INI file into easy-to-access name/value pairs.

#include <algorithm>
#include <cctype>
#include <cstdlib>

#include "ini.h"
#include "config.h"

using std::string;

config::config(string filename)
    : _filename(filename) {}

bool config::parse() {
  _error = ini_parse(_filename.c_str(), ValueHandler, this);
  if (_error < 0) {
    std::cout << "parse ini failed\n";
    return false;
  }

  server.ip = Get("server", "serv_ip", "192.168.44.129");
  server.port = GetInteger("server", "serv_port", 53);
  log.level = GetInteger("log", "level", 6);

  return true;
}

int config::ParseError() {
  return _error;
}

string config::Get(string section, string name, string default_value) {
  string key = MakeKey(section, name);
  return _values.count(key) ? _values[key] : default_value;
}

long config::GetInteger(string section, string name, long default_value) {
  string valstr = Get(section, name, "");
  const char *value = valstr.c_str();
  char *end;
  // This parses "1234" (decimal) and also "0x4D2" (hex)
  long n = strtol(value, &end, 0);
  return end > value ? n : default_value;
}

double config::GetReal(string section, string name, double default_value) {
  string valstr = Get(section, name, "");
  const char *value = valstr.c_str();
  char *end;
  double n = strtod(value, &end);
  return end > value ? n : default_value;
}

bool config::GetBoolean(string section, string name, bool default_value) {
  string valstr = Get(section, name, "");
  // Convert to lower case to make string comparisons case-insensitive
  std::transform(valstr.begin(), valstr.end(), valstr.begin(), ::tolower);
  if (valstr == "true" || valstr == "yes" || valstr == "on" || valstr == "1")
    return true;
  else if (valstr == "false" || valstr == "no" || valstr == "off" || valstr == "0")
    return false;
  else
    return default_value;
}

std::vector<std::string> config::GetSections() const {
  return _sections;
}

string config::MakeKey(string section, string name) {
  string key = section + "." + name;
  // Convert to lower case to make section/name lookups case-insensitive
  std::transform(key.begin(), key.end(), key.begin(), ::tolower);
  return key;
}

int config::ValueHandler(void *user, const char *section,
                         const char *name, const char *value) {
  config *reader = (config *) user;
  string key = MakeKey(section, name);
  if (reader->_values[key].size() > 0)
    reader->_values[key] += "\n";
  reader->_values[MakeKey(section, name)] = value;

  std::vector<std::string>::iterator sec_beg = reader->_sections.begin();
  std::vector<std::string>::iterator sec_end = reader->_sections.end();
  if (std::find(sec_beg, sec_end, section) == reader->_sections.end())
    reader->_sections.push_back(section);
  return 1;
}
