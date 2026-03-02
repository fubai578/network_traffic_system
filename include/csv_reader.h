#ifndef CSV_READER_H
#define CSV_READER_H

#include "types.h"
#include <vector>
#include <string>

//CSV数据读取模块：解析network_data.csv为SessionRecord结构
class CsvReader {
public:
    //从指定路径读取CSV数据，解析为会话记录列表（成功返回true，失败返回false）
    static bool load(const std::string& filepath,
                     std::vector<SessionRecord>& records);

private:
    //将CSV一行按逗号分割为字段列表
    static std::vector<std::string> split(const std::string& line);
    //去除字符串首尾空白和引号
    static std::string trim(const std::string& s);
};

#endif // CSV_READER_H