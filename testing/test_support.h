// Copyright 2015 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_TEST_SUPPORT_H_
#define TESTING_TEST_SUPPORT_H_

#include <stdlib.h>

#include <memory>
#include <string>
#include <vector>

#include "public/fpdfview.h"

#ifdef PDF_ENABLE_XFA
class CFGAS_FontMgr;
#endif  // PDF_ENABLE_XFA

namespace pdfium {

#define STR_IN_TEST_CASE(input_literal, ...)               \
  {                                                        \
    reinterpret_cast<const unsigned char*>(input_literal), \
        sizeof(input_literal) - 1, __VA_ARGS__             \
  }

#define STR_IN_OUT_CASE(input_literal, expected_literal, ...)     \
  {                                                               \
    reinterpret_cast<const unsigned char*>(input_literal),        \
        sizeof(input_literal) - 1,                                \
        reinterpret_cast<const unsigned char*>(expected_literal), \
        sizeof(expected_literal) - 1, __VA_ARGS__                 \
  }

struct StrFuncTestData {
  const unsigned char* input;
  uint32_t input_size;
  const unsigned char* expected;
  uint32_t expected_size;
};

struct DecodeTestData {
  const unsigned char* input;
  uint32_t input_size;
  const unsigned char* expected;
  uint32_t expected_size;
  // The size of input string being processed.
  uint32_t processed_size;
};

struct NullTermWstrFuncTestData {
  const wchar_t* input;
  const wchar_t* expected;
};

// Used with std::unique_ptr to free() objects that can't be deleted.
struct FreeDeleter {
  inline void operator()(void* ptr) const { free(ptr); }
};

}  // namespace pdfium

// Reads the entire contents of a file into a newly alloc'd buffer.
std::unique_ptr<char, pdfium::FreeDeleter> GetFileContents(const char* filename,
                                                           size_t* retlen);

std::vector<std::string> StringSplit(const std::string& str, char delimiter);

// Converts a FPDF_WIDESTRING to a std::string.
// Deals with differences between UTF16LE and UTF8.
std::string GetPlatformString(FPDF_WIDESTRING wstr);

// Converts a FPDF_WIDESTRING to a std::wstring.
// Deals with differences between UTF16LE and wchar_t.
std::wstring GetPlatformWString(FPDF_WIDESTRING wstr);

// Returns a newly allocated FPDF_WIDESTRING.
// Deals with differences between UTF16LE and wchar_t.
std::unique_ptr<unsigned short, pdfium::FreeDeleter> GetFPDFWideString(
    const std::wstring& wstr);

#ifdef PDF_ENABLE_XFA
CFGAS_FontMgr* GetGlobalFontManager();
#endif  // PDF_ENABLE_XFA

#endif  // TESTING_TEST_SUPPORT_H_
