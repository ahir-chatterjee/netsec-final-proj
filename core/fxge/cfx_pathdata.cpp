// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxge/cfx_pathdata.h"

#include "core/fxcrt/fx_system.h"
#include "third_party/base/check.h"
#include "third_party/base/numerics/safe_math.h"

namespace {

bool IsRectPreTransform(const std::vector<FX_PATHPOINT>& points) {
  if (points.size() != 5 && points.size() != 4)
    return false;

  if (points.size() == 5 && points[0].m_Point != points[4].m_Point)
    return false;

  if (points[0].m_Point == points[2].m_Point ||
      points[1].m_Point == points[3].m_Point) {
    return false;
  }

  for (size_t i = 1; i < points.size(); ++i) {
    if (points[i].m_Type != FXPT_TYPE::LineTo)
      return false;
  }
  return true;
}

bool XYBothNotEqual(const CFX_PointF& p1, const CFX_PointF& p2) {
  return p1.x != p2.x && p1.y != p2.y;
}

CFX_FloatRect CreateRectFromPoints(const CFX_PointF& p1, const CFX_PointF& p2) {
  CFX_FloatRect rect(p1.x, p1.y, p2.x, p2.y);
  rect.Normalize();
  return rect;
}

void UpdateLineEndPoints(CFX_FloatRect* rect,
                         const CFX_PointF& start_pos,
                         const CFX_PointF& end_pos,
                         float hw) {
  if (start_pos.x == end_pos.x) {
    if (start_pos.y == end_pos.y) {
      rect->UpdateRect(end_pos + CFX_PointF(hw, hw));
      rect->UpdateRect(end_pos - CFX_PointF(hw, hw));
      return;
    }

    float point_y;
    if (end_pos.y < start_pos.y)
      point_y = end_pos.y - hw;
    else
      point_y = end_pos.y + hw;

    rect->UpdateRect(CFX_PointF(end_pos.x + hw, point_y));
    rect->UpdateRect(CFX_PointF(end_pos.x - hw, point_y));
    return;
  }

  if (start_pos.y == end_pos.y) {
    float point_x;
    if (end_pos.x < start_pos.x)
      point_x = end_pos.x - hw;
    else
      point_x = end_pos.x + hw;

    rect->UpdateRect(CFX_PointF(point_x, end_pos.y + hw));
    rect->UpdateRect(CFX_PointF(point_x, end_pos.y - hw));
    return;
  }

  CFX_PointF diff = end_pos - start_pos;
  float ll = FXSYS_sqrt2(diff.x, diff.y);
  float mx = end_pos.x + hw * diff.x / ll;
  float my = end_pos.y + hw * diff.y / ll;
  float dx1 = hw * diff.y / ll;
  float dy1 = hw * diff.x / ll;
  rect->UpdateRect(CFX_PointF(mx - dx1, my + dy1));
  rect->UpdateRect(CFX_PointF(mx + dx1, my - dy1));
}

void UpdateLineJoinPoints(CFX_FloatRect* rect,
                          const CFX_PointF& start_pos,
                          const CFX_PointF& mid_pos,
                          const CFX_PointF& end_pos,
                          float half_width,
                          float miter_limit) {
  float start_k = 0;
  float start_c = 0;
  float end_k = 0;
  float end_c = 0;
  float start_len = 0;
  float start_dc = 0;
  float end_len = 0;
  float end_dc = 0;
  float one_twentieth = 1.0f / 20;

  bool bStartVert = fabs(start_pos.x - mid_pos.x) < one_twentieth;
  bool bEndVert = fabs(mid_pos.x - end_pos.x) < one_twentieth;
  if (bStartVert && bEndVert) {
    int start_dir = mid_pos.y > start_pos.y ? 1 : -1;
    float point_y = mid_pos.y + half_width * start_dir;
    rect->UpdateRect(CFX_PointF(mid_pos.x + half_width, point_y));
    rect->UpdateRect(CFX_PointF(mid_pos.x - half_width, point_y));
    return;
  }

  if (!bStartVert) {
    CFX_PointF start_to_mid = start_pos - mid_pos;
    start_k = (mid_pos.y - start_pos.y) / (mid_pos.x - start_pos.x);
    start_c = mid_pos.y - (start_k * mid_pos.x);
    start_len = FXSYS_sqrt2(start_to_mid.x, start_to_mid.y);
    start_dc =
        static_cast<float>(fabs(half_width * start_len / start_to_mid.x));
  }
  if (!bEndVert) {
    CFX_PointF end_to_mid = end_pos - mid_pos;
    end_k = end_to_mid.y / end_to_mid.x;
    end_c = mid_pos.y - (end_k * mid_pos.x);
    end_len = FXSYS_sqrt2(end_to_mid.x, end_to_mid.y);
    end_dc = static_cast<float>(fabs(half_width * end_len / end_to_mid.x));
  }
  if (bStartVert) {
    CFX_PointF outside(start_pos.x, 0);
    if (end_pos.x < start_pos.x)
      outside.x += half_width;
    else
      outside.x -= half_width;

    if (start_pos.y < (end_k * start_pos.x) + end_c)
      outside.y = (end_k * outside.x) + end_c + end_dc;
    else
      outside.y = (end_k * outside.x) + end_c - end_dc;

    rect->UpdateRect(outside);
    return;
  }

  if (bEndVert) {
    CFX_PointF outside(end_pos.x, 0);
    if (start_pos.x < end_pos.x)
      outside.x += half_width;
    else
      outside.x -= half_width;

    if (end_pos.y < (start_k * end_pos.x) + start_c)
      outside.y = (start_k * outside.x) + start_c + start_dc;
    else
      outside.y = (start_k * outside.x) + start_c - start_dc;

    rect->UpdateRect(outside);
    return;
  }

  if (fabs(start_k - end_k) < one_twentieth) {
    int start_dir = mid_pos.x > start_pos.x ? 1 : -1;
    int end_dir = end_pos.x > mid_pos.x ? 1 : -1;
    if (start_dir == end_dir)
      UpdateLineEndPoints(rect, mid_pos, end_pos, half_width);
    else
      UpdateLineEndPoints(rect, start_pos, mid_pos, half_width);
    return;
  }

  float start_outside_c = start_c;
  if (end_pos.y < (start_k * end_pos.x) + start_c)
    start_outside_c += start_dc;
  else
    start_outside_c -= start_dc;

  float end_outside_c = end_c;
  if (start_pos.y < (end_k * start_pos.x) + end_c)
    end_outside_c += end_dc;
  else
    end_outside_c -= end_dc;

  float join_x = (end_outside_c - start_outside_c) / (start_k - end_k);
  float join_y = start_k * join_x + start_outside_c;
  rect->UpdateRect(CFX_PointF(join_x, join_y));
}

}  // namespace

FX_PATHPOINT::FX_PATHPOINT() = default;

FX_PATHPOINT::FX_PATHPOINT(const CFX_PointF& point, FXPT_TYPE type, bool close)
    : m_Point(point), m_Type(type), m_CloseFigure(close) {}

FX_PATHPOINT::FX_PATHPOINT(const FX_PATHPOINT& other) = default;

FX_PATHPOINT::~FX_PATHPOINT() = default;

CFX_PathData::CFX_PathData() = default;

CFX_PathData::CFX_PathData(const CFX_PathData& src) = default;

CFX_PathData::CFX_PathData(CFX_PathData&& src) noexcept = default;

CFX_PathData::~CFX_PathData() = default;

void CFX_PathData::Clear() {
  m_Points.clear();
}

void CFX_PathData::ClosePath() {
  if (m_Points.empty())
    return;
  m_Points.back().m_CloseFigure = true;
}

void CFX_PathData::Append(const CFX_PathData& src, const CFX_Matrix* matrix) {
  if (src.m_Points.empty())
    return;

  size_t cur_size = m_Points.size();
  m_Points.insert(m_Points.end(), src.m_Points.begin(), src.m_Points.end());

  if (!matrix)
    return;

  for (size_t i = cur_size; i < m_Points.size(); i++)
    m_Points[i].m_Point = matrix->Transform(m_Points[i].m_Point);
}

void CFX_PathData::AppendPoint(const CFX_PointF& point, FXPT_TYPE type) {
  m_Points.push_back(FX_PATHPOINT(point, type, /*close=*/false));
}

void CFX_PathData::AppendPointAndClose(const CFX_PointF& point,
                                       FXPT_TYPE type) {
  m_Points.push_back(FX_PATHPOINT(point, type, /*close=*/true));
}

void CFX_PathData::AppendLine(const CFX_PointF& pt1, const CFX_PointF& pt2) {
  if (m_Points.empty() || fabs(m_Points.back().m_Point.x - pt1.x) > 0.001 ||
      fabs(m_Points.back().m_Point.y - pt1.y) > 0.001) {
    AppendPoint(pt1, FXPT_TYPE::MoveTo);
  }
  AppendPoint(pt2, FXPT_TYPE::LineTo);
}

void CFX_PathData::AppendFloatRect(const CFX_FloatRect& rect) {
  return AppendRect(rect.left, rect.bottom, rect.right, rect.top);
}

void CFX_PathData::AppendRect(float left,
                              float bottom,
                              float right,
                              float top) {
  CFX_PointF left_bottom(left, bottom);
  CFX_PointF left_top(left, top);
  CFX_PointF right_top(right, top);
  CFX_PointF right_bottom(right, bottom);

  AppendLine(left_bottom, left_top);
  AppendLine(left_top, right_top);
  AppendLine(right_top, right_bottom);
  AppendLine(right_bottom, left_bottom);
  ClosePath();
}

CFX_FloatRect CFX_PathData::GetBoundingBox() const {
  if (m_Points.empty())
    return CFX_FloatRect();

  CFX_FloatRect rect;
  rect.InitRect(m_Points[0].m_Point);
  for (size_t i = 1; i < m_Points.size(); i++)
    rect.UpdateRect(m_Points[i].m_Point);
  return rect;
}

CFX_FloatRect CFX_PathData::GetBoundingBox(float line_width,
                                           float miter_limit) const {
  CFX_FloatRect rect(100000.0f, 100000.0f, -100000.0f, -100000.0f);
  size_t iPoint = 0;
  float half_width = line_width;
  int iStartPoint = 0;
  int iEndPoint = 0;
  int iMiddlePoint = 0;
  bool bJoin;
  while (iPoint < m_Points.size()) {
    if (m_Points[iPoint].IsTypeAndOpen(FXPT_TYPE::MoveTo)) {
      if (iPoint + 1 == m_Points.size())
        break;

      iStartPoint = iPoint + 1;
      iEndPoint = iPoint;
      bJoin = false;
    } else {
      if (m_Points[iPoint].IsTypeAndOpen(FXPT_TYPE::BezierTo)) {
        rect.UpdateRect(m_Points[iPoint].m_Point);
        rect.UpdateRect(m_Points[iPoint + 1].m_Point);
        iPoint += 2;
      }
      if (iPoint == m_Points.size() - 1 ||
          m_Points[iPoint + 1].IsTypeAndOpen(FXPT_TYPE::MoveTo)) {
        iStartPoint = iPoint - 1;
        iEndPoint = iPoint;
        bJoin = false;
      } else {
        iStartPoint = iPoint - 1;
        iMiddlePoint = iPoint;
        iEndPoint = iPoint + 1;
        bJoin = true;
      }
    }

    CFX_PointF start_pos = m_Points[iStartPoint].m_Point;
    CFX_PointF end_pos = m_Points[iEndPoint].m_Point;
    if (bJoin) {
      CFX_PointF mid_pos = m_Points[iMiddlePoint].m_Point;
      UpdateLineJoinPoints(&rect, start_pos, mid_pos, end_pos, half_width,
                           miter_limit);
    } else {
      UpdateLineEndPoints(&rect, start_pos, end_pos, half_width);
    }
    iPoint++;
  }
  return rect;
}

void CFX_PathData::Transform(const CFX_Matrix& matrix) {
  for (auto& point : m_Points)
    point.m_Point = matrix.Transform(point.m_Point);
}

bool CFX_PathData::IsRect() const {
  if (!IsRectPreTransform(m_Points))
    return false;

  for (int i = 1; i < 4; i++) {
    if (XYBothNotEqual(m_Points[i].m_Point, m_Points[i - 1].m_Point))
      return false;
  }

  if (XYBothNotEqual(m_Points[0].m_Point, m_Points[3].m_Point))
    return false;

  return true;
}

Optional<CFX_FloatRect> CFX_PathData::GetRect(const CFX_Matrix* matrix) const {
  if (!matrix) {
    if (!IsRect())
      return pdfium::nullopt;

    return CreateRectFromPoints(m_Points[0].m_Point, m_Points[2].m_Point);
  }

  if (!IsRectPreTransform(m_Points))
    return pdfium::nullopt;

  CFX_PointF points[5];
  for (size_t i = 0; i < m_Points.size(); ++i) {
    points[i] = matrix->Transform(m_Points[i].m_Point);

    if (i == 0)
      continue;
    if (XYBothNotEqual(points[i], points[i - 1]))
      return pdfium::nullopt;
  }

  if (XYBothNotEqual(points[0], points[3]))
    return pdfium::nullopt;

  return CreateRectFromPoints(points[0], points[2]);
}

CFX_RetainablePathData::CFX_RetainablePathData() = default;

// Note: can't default the copy constructor since Retainable<> has a deleted
// copy constructor (as it should). Instead, we want the default Retainable<>
// constructor to be invoked so as to create a copy with a ref-count of 1 as
// of the time it is created, then populate the remainder of the members from
// the |src| object.
CFX_RetainablePathData::CFX_RetainablePathData(
    const CFX_RetainablePathData& src)
    : CFX_PathData(src) {}

CFX_RetainablePathData::~CFX_RetainablePathData() = default;

RetainPtr<CFX_RetainablePathData> CFX_RetainablePathData::Clone() const {
  return pdfium::MakeRetain<CFX_RetainablePathData>(*this);
}
