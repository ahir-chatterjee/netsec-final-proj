// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/css/cfx_cssselector.h"

#include <utility>

#include "core/fxcrt/fx_extension.h"

namespace {

size_t GetCSSNameLen(WideStringView str) {
  for (size_t i = 0; i < str.GetLength(); ++i) {
    wchar_t wch = str[i];
    if (!isascii(wch) || (!isalnum(wch) && wch != '_' && wch != '-'))
      return i;
  }
  return str.GetLength();
}

}  // namespace

CFX_CSSSelector::CFX_CSSSelector(WideStringView str,
                                 std::unique_ptr<CFX_CSSSelector> next)
    : name_hash_(FX_HashCode_GetW(str, /*bIgnoreCase=*/true)),
      next_(std::move(next)) {}

CFX_CSSSelector::~CFX_CSSSelector() = default;

// static.
std::unique_ptr<CFX_CSSSelector> CFX_CSSSelector::FromString(
    WideStringView str) {
  ASSERT(!str.IsEmpty());

  for (wchar_t wch : str) {
    switch (wch) {
      case '>':
      case '[':
      case '+':
        return nullptr;
    }
  }

  std::unique_ptr<CFX_CSSSelector> head;
  for (size_t i = 0; i < str.GetLength();) {
    wchar_t wch = str[i];
    if ((isascii(wch) && isalpha(wch)) || wch == '*') {
      if (head)
        head->set_is_descendant();
      size_t len =
          wch == '*' ? 1 : GetCSSNameLen(str.Last(str.GetLength() - i));
      auto new_head = std::make_unique<CFX_CSSSelector>(str.Substr(i, len),
                                                        std::move(head));
      head = std::move(new_head);
      i += len;
    } else if (wch == ' ') {
      ++i;
    } else {
      return nullptr;
    }
  }
  return head;
}
