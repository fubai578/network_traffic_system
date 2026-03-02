#include "../include/csv_reader.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cctype>

//去除字符串首尾空白和引号
std::string CsvReader::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n\"");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n\"");
    return s.substr(start, end - start + 1);
}

//按逗号分割CSV行
std::vector<std::string> CsvReader::split(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream ss(line);
    std::string field;
    while (std::getline(ss, field, ',')) {
        fields.push_back(trim(field));
    }
    return fields;
}

//从文件加载CSV数据
bool CsvReader::load(const std::string& filepath,
                     std::vector<SessionRecord>& records) {
    std::ifstream ifs(filepath);
    if (!ifs.is_open()) {
        std::cerr << "[Error] Cannot open file: " << filepath << std::endl;
        return false;
    }

    records.clear();
    std::string line;
    int line_no = 0;
    int skipped = 0;

    //跳过头部行
    if (!std::getline(ifs, line)) {
        std::cerr << "[Error] File is empty" << std::endl;
        return false;
    }
    line_no++;

    while (std::getline(ifs, line)) {
        line_no++;
        if (line.empty()) continue;

        auto fields = split(line);
        if (fields.size() < 7) {
            skipped++;
            continue;
        }

        try {
            SessionRecord rec;
            rec.src_ip    = fields[0];
            rec.dst_ip    = fields[1];
            rec.protocol  = std::stoi(fields[2]);
            rec.src_port  = std::stoi(fields[3]);
            rec.dst_port  = std::stoi(fields[4]);
            rec.data_size = std::stoll(fields[5]);
            rec.duration  = std::stod(fields[6]);

            if (rec.src_ip.empty() || rec.dst_ip.empty()) {
                skipped++;
                continue;
            }
            records.push_back(rec);
        } catch (const std::exception& e) {
            skipped++;
        }
    }

    std::cout << "[CSV] Loaded " << records.size()
              << " records, skipped " << skipped << " invalid lines." << std::endl;
    return true;
}
