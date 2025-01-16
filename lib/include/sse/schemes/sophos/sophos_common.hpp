//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//

#pragma once

#include "../../../../../third_party/crypto/src/include/sse/crypto/key.hpp"
#include "../../../../../third_party/crypto/src/include/sse/crypto/prf.hpp"
#include "../../../../../third_party/crypto/src/include/sse/crypto/tdp.hpp"

#include <array>
#include <string>
#include<map>
#include <vector>
#include <fstream>

namespace sse {
namespace sophos {

constexpr size_t kSearchTokenSize   = crypto::Tdp::kMessageSize;
constexpr size_t kDerivationKeySize = 32;
constexpr size_t kUpdateTokenSize   = 16;

using search_token_type = std::array<uint8_t, kSearchTokenSize>;
using update_token_type = std::array<uint8_t, kUpdateTokenSize>;
using index_type        = uint64_t;

extern std::string storage_dir_path  ;
extern std::string table_file;

enum class sse_kind
{
  UNDEFINED,   ///< 没有用SSE
  FIDES,     
  MAXTYPE,   ///< 请在 UNDEFINED 与 MAXTYPE 之间增加新类型     
};

struct sse_col
{
    std::string col_name;
    sse_kind kind;
};

extern std::map<std::string, std::vector<sse_col>> sse_table_map;

void table_map_init(const std::string& table_map_path);

// 向文件中追加写入一条字典记录
void appendTableMap(const std::string& tableName, const std::vector<sse_col>& columns, const std::string& filename);

// 将字典内容覆盖写入文件
void writeTableMap(const std::map<std::string, std::vector<sse_col>>& sse_table_map, const std::string& filename);

struct SearchRequest
{
    search_token_type                       token;
    std::array<uint8_t, kDerivationKeySize> derivation_key;
    uint32_t                                add_count;
};


struct UpdateRequest
{
    update_token_type token;
    index_type        index;
};

const char *sse_kind_to_string(sse_kind type);
sse_kind    sse_kind_from_string(const char *s);

static inline bool is_base64(unsigned char c);
std::string base64_encode(const std::string &data);
std::string base64_decode(std::string const& encoded_string);

std::string parser_create_table(std::string createTableSQL);
std::string getTableNameFromInsertSQL(std::string insertSQL);
std::string getTableNameFromSelectSQL(std::string selectSQL);
std::string getTableNameFromDeleteSQL(std::string deleteSQL);
std::string double_quote_values(const std::string &sql) ;

void gen_update_token_masks(const crypto::Prf<kUpdateTokenSize>& derivation_prf,
                            const uint8_t*                       search_token,
                            update_token_type&                   update_token,
                            std::array<uint8_t, kUpdateTokenSize>& mask);
} // namespace sophos
} // namespace sse
