// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com
// We're going to use RLBox in a single-threaded environment.
#define RLBOX_SINGLE_THREADED_INVOCATIONS
// All calls into the sandbox are resolved statically.
#define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol

#include <core/fxcodec/tiff/rlbox/code/include/rlbox.hpp>
#include <core/fxcodec/tiff/rlbox/code/include/rlbox_noop_sandbox.hpp>

#include "core/fxcodec/tiff/tiff_decoder.h"

#include <limits>
#include <memory>

#include "core/fxcodec/cfx_codec_memory.h"
#include "core/fxcodec/fx_codec.h"
#include "core/fxcodec/fx_codec_def.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxcrt/fx_stream.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/retain_ptr.h"
#include "core/fxge/dib/cfx_dibitmap.h"
#include "core/fxge/dib/fx_dib.h"
#include "third_party/base/check.h"
#include "third_party/base/notreached.h"
#include "third_party/base/numerics/safe_conversions.h"

extern "C" {
#include "third_party/libtiff/tiffiop.h"
}  // extern C

namespace {

// from https://github.com/ayushagarwal95/tutorial-rlbox
using rlbox_sandbox_tiff = rlbox::rlbox_noop_sandbox;
using rlbox_sandbox_libtiff = rlbox::rlbox_sandbox<rlbox_sandbox_tiff>;
template <typename T>
using rlbox_sandbox_callback_tiff = rlbox::sandbox_callback<T, rlbox_sandbox_tiff>;

rlbox_sandbox_libtiff* CreateSandbox() {
    rlbox_sandbox_libtiff* sandbox = new rlbox_sandbox_libtiff();
    sandbox->create_sandbox();
    return sandbox;
}

void DeleteSandbox (rlbox_sandbox_libtiff *sandbox) {
  sandbox->destroy_sandbox();
  delete sandbox;
}

// For use with std::unique_ptr<TIFF>.
struct TiffDeleter {
  inline void operator()(TIFF* context) { TIFFClose(context); }
};

}  // namespace

class CTiffContext final : public ProgressiveDecoderIface::Context {
 public:
  CTiffContext();
  ~CTiffContext();
  //~CTiffContext() override = default;

  bool InitDecoder(const RetainPtr<IFX_SeekableReadStream>& file_ptr);
  bool LoadFrameInfo(int32_t frame,
                     int32_t* width,
                     int32_t* height,
                     int32_t* comps,
                     int32_t* bpc,
                     CFX_DIBAttribute* pAttribute);
  bool Decode(const RetainPtr<CFX_DIBitmap>& pDIBitmap);

  RetainPtr<IFX_SeekableReadStream> io_in() const { return m_io_in; }
  uint32_t offset() const { return m_offset; }
  void set_offset(uint32_t offset) { m_offset = offset; }

 private:
  bool IsSupport(const RetainPtr<CFX_DIBitmap>& pDIBitmap) const;
  void SetPalette(const RetainPtr<CFX_DIBitmap>& pDIBitmap, uint16_t bps);
  bool Decode1bppRGB(const RetainPtr<CFX_DIBitmap>& pDIBitmap,
                     int32_t height,
                     int32_t width,
                     uint16_t bps,
                     uint16_t spp);
  bool Decode8bppRGB(const RetainPtr<CFX_DIBitmap>& pDIBitmap,
                     int32_t height,
                     int32_t width,
                     uint16_t bps,
                     uint16_t spp);
  bool Decode24bppRGB(const RetainPtr<CFX_DIBitmap>& pDIBitmap,
                      int32_t height,
                      int32_t width,
                      uint16_t bps,
                      uint16_t spp);

  RetainPtr<IFX_SeekableReadStream> m_io_in;
  uint32_t m_offset = 0;
  std::unique_ptr<TIFF, TiffDeleter> m_tif_ctx;
  
  // RLBOX instance vars
  rlbox_sandbox_libtiff* tiff_sb;
  rlbox::tainted<TIFF*, rlbox_sandbox_tiff> tiff_ctx;
  rlbox_sandbox_callback_tiff<tsize_t (*) (thandle_t, tdata_t, tsize_t)> sb_tiff_read;
  rlbox_sandbox_callback_tiff<tsize_t (*)(thandle_t, tdata_t, tsize_t)> sb_tiff_write;
  rlbox_sandbox_callback_tiff<toff_t (*)(thandle_t, toff_t, int)> sb_tiff_seek;
  rlbox_sandbox_callback_tiff<int (*)(thandle_t)> sb_tiff_close;
  rlbox_sandbox_callback_tiff<toff_t (*)(thandle_t)> sb_tiff_get_size;
  rlbox_sandbox_callback_tiff<int (*)(thandle_t, tdata_t*, toff_t*)> sb_tiff_map;
  rlbox_sandbox_callback_tiff<void (*)(thandle_t, tdata_t, toff_t)> sb_tiff_unmap;
};

  // RLBOX: need deconstructor for sandbox deletion
  CTiffContext::CTiffContext(){
  // create sandbox
  tiff_sb = CreateSandbox();


}

CTiffContext::~CTiffContext(){
  sb_tiff_read.unregister();
  sb_tiff_close.unregister();
  sb_tiff_get_size.unregister();
  sb_tiff_map.unregister();
  sb_tiff_seek.unregister();
  sb_tiff_unmap.unregister();
  sb_tiff_write.unregister();
  tiff_sb->free_in_sandbox(tiff_ctx);
  DeleteSandbox(tiff_sb);
}

void* _TIFFcalloc(tmsize_t nmemb, tmsize_t siz) {
  return FXMEM_DefaultCalloc(nmemb, siz);
}

void* _TIFFmalloc(tmsize_t size) {
  return FXMEM_DefaultAlloc(size);
}

void _TIFFfree(void* ptr) {
  if (ptr)
    FXMEM_DefaultFree(ptr);
}

void* _TIFFrealloc(void* ptr, tmsize_t size) {
  return FXMEM_DefaultRealloc(ptr, size);
}

void _TIFFmemset(void* ptr, int val, tmsize_t size) {
  memset(ptr, val, static_cast<size_t>(size));
}

void _TIFFmemcpy(void* des, const void* src, tmsize_t size) {
  memcpy(des, src, static_cast<size_t>(size));
}

int _TIFFmemcmp(const void* ptr1, const void* ptr2, tmsize_t size) {
  return memcmp(ptr1, ptr2, static_cast<size_t>(size));
}

TIFFErrorHandler _TIFFwarningHandler = nullptr;
TIFFErrorHandler _TIFFerrorHandler = nullptr;

namespace {

// fairly sure this method is correctly sandboxed
rlbox::tainted<tsize_t, rlbox::rlbox_noop_sandbox> tiff_read(rlbox_sandbox_tiff& sbx, rlbox::tainted<thandle_t, rlbox::rlbox_noop_sandbox> taintedContext, rlbox::tainted<tdata_t, rlbox::rlbox_noop_sandbox> taintedBuf, rlbox::tainted<tsize_t, rlbox::rlbox_noop_sandbox> taintedLength) {
  size_t length = taintedLength.copy_and_verify([](size_t ret){
    // check for positive length
    if (ret < 0) {
      return false;
    }
    return true;
  });
  CTiffContext* pTiffContext = reinterpret_cast<CTiffContext*>(sbx.sandbox_storage);
  FX_SAFE_UINT32 increment = pTiffContext->offset();
  increment += length;
  if (!increment.IsValid())
    //increment is invalid, read failed, return 0. also checks the validity of length above
    return 0;
 
  FX_FILESIZE offset = pTiffContext->offset();
  // create new buf to avoid taintedBuf completely
  tdata_t buf = malloc(length);
  if (!buf)
    return 0;
  bzero(buf, length); // zero out the temp buffer
  if (!pTiffContext->io_in()->ReadBlockAtOffset(buf, offset, length)) {
    // read failed, return 0
    free(buf);
    return 0;
  }
  rlbox::memcpy(sbx, taintedBuf, buf, taintedLength); // copy everything into our sandbox
  free(buf);  // temp buf is no longer needed
 
  pTiffContext->set_offset(increment.ValueOrDie());
  if (offset + length > pTiffContext->io_in()->GetSize()) {
    return pdfium::base::checked_cast<tsize_t>(
        pTiffContext->io_in()->GetSize() - offset);
  }
  return length;
 }

rlbox::tainted<tsize_t, rlbox::rlbox_noop_sandbox> tiff_write(rlbox_sandbox_tiff& sbx, rlbox::tainted<thandle_t, rlbox::rlbox_noop_sandbox> taintedContext, rlbox::tainted<tdata_t, rlbox::rlbox_noop_sandbox> taintedBuf, rlbox::tainted<tsize_t, rlbox::rlbox_noop_sandbox> taintedLength) {
  NOTREACHED(); //essentially crashes the program, nbd because it shouldn't be called
  return 0;
}

rlbox::tainted<toff_t, rlbox::rlbox_noop_sandbox> tiff_seek(rlbox_sandbox_tiff& sbx, rlbox::tainted<thandle_t, rlbox::rlbox_noop_sandbox> taintedContext, rlbox::tainted<toff_t, rlbox::rlbox_noop_sandbox> taintedOffset, rlbox::tainted<int, rlbox::rlbox_noop_sandbox> taintedWhence) {
  CTiffContext* pTiffContext = reinterpret_cast<CTiffContext*>(sbx.sandbox_storage);
  FX_SAFE_FILESIZE safe_offset = taintedOffset.copy_and_verify([](size_t ret){
    // check for positive offset
    if (ret < 0) {
      return false;
    }
    return true;
  });
  if (!safe_offset.IsValid())
    return static_cast<toff_t>(-1);
  FX_FILESIZE file_offset = safe_offset.ValueOrDie();
 
  int whence = taintedWhence.copy_and_verify([](int ret){return true;}); 
  switch (whence) {
    case 0: {
      if (file_offset > pTiffContext->io_in()->GetSize())
        return static_cast<toff_t>(-1);
      pTiffContext->set_offset(
          pdfium::base::checked_cast<uint32_t>(file_offset));
      return pTiffContext->offset();
    }
    case 1: {
      FX_SAFE_UINT32 new_increment = pTiffContext->offset();
      new_increment += file_offset;
      if (!new_increment.IsValid())
        return static_cast<toff_t>(-1);
      pTiffContext->set_offset(new_increment.ValueOrDie());
      return pTiffContext->offset();
    }
    case 2: {
      if (pTiffContext->io_in()->GetSize() < file_offset)
        return static_cast<toff_t>(-1);
      pTiffContext->set_offset(pdfium::base::checked_cast<uint32_t>(
          pTiffContext->io_in()->GetSize() - file_offset));
      return pTiffContext->offset();
    }
    default:
      return static_cast<toff_t>(-1);
  }
}

rlbox::tainted<int, rlbox::rlbox_noop_sandbox> tiff_close(rlbox_sandbox_tiff& sbx, rlbox::tainted<thandle_t, rlbox::rlbox_noop_sandbox> taintedContext) {
  return 0;
}

rlbox::tainted<toff_t, rlbox::rlbox_noop_sandbox> tiff_get_size(rlbox_sandbox_tiff& sbx, rlbox::tainted<thandle_t, rlbox::rlbox_noop_sandbox> context) {
  CTiffContext* pTiffContext = reinterpret_cast<CTiffContext*>(sbx.sandbox_storage);
  return static_cast<toff_t>(pTiffContext->io_in()->GetSize());
}

rlbox::tainted<int, rlbox::rlbox_noop_sandbox> tiff_map(rlbox::tainted<thandle_t, rlbox::rlbox_noop_sandbox> context, rlbox::tainted<tdata_t*, rlbox::rlbox_noop_sandbox>, rlbox::tainted<toff_t*, rlbox::rlbox_noop_sandbox>) {
  return 0;
}

void tiff_unmap(rlbox::tainted<thandle_t, rlbox::rlbox_noop_sandbox> context, rlbox::tainted<tdata_t, rlbox::rlbox_noop_sandbox>, rlbox::tainted<toff_t, rlbox::rlbox_noop_sandbox>) {}

/*
rlbox::tainted<TIFF*, rlbox_sandbox_tiff> tiff_open(void* context, const char* mode) {
  // TODO: SANDBOX
  sb_tiff_read = tiff_sb->register_callback(tiff_read);
  sb_tiff_write = tiff_sb->register_callback(tiff_write);
  sb_tiff_seek = tiff_sb->register_callback(tiff_seek);
  sb_tiff_close = tiff_sb->register_callback(tiff_close);
  sb_tiff_get_size = tiff_sb->register_callback(tiff_get_size);
  sb_tiff_map = tiff_sb->register_callback(tiff_map);
  sb_tiff_unmap = tiff_sb->register_callback(tiff_unmap);

  sb_tiff_name = rlbox::sandbox_str(tiff_sb, "Tiff Image", )
  TIFF* tif = TIFFClientOpen("Tiff Image", mode, (thandle_t)context, tiff_read,
                             tiff_write, tiff_seek, tiff_close, tiff_get_size,
                             tiff_map, tiff_unmap);
  if (tif) {
    tif->tif_fd = (int)(intptr_t)context;
  }
  return tif;
}
*/
void TiffBGRA2RGBA(uint8_t* pBuf, int32_t pixel, int32_t spp) {
  for (int32_t n = 0; n < pixel; n++) {
    uint8_t tmp = pBuf[0];
    pBuf[0] = pBuf[2];
    pBuf[2] = tmp;
    pBuf += spp;
  }
}

}  // namespace

bool CTiffContext::InitDecoder(
    const RetainPtr<IFX_SeekableReadStream>& file_ptr) {

  // somehow put "this" into sandbox
  m_io_in = file_ptr;
  
  sb_tiff_read = tiff_sb->register_callback(tiff_read);
  sb_tiff_write = tiff_sb->register_callback(tiff_write);
  sb_tiff_seek = tiff_sb->register_callback(tiff_seek);
  sb_tiff_close = tiff_sb->register_callback(tiff_close);
  sb_tiff_get_size = tiff_sb->register_callback(tiff_get_size);
  sb_tiff_map = tiff_sb->register_callback(tiff_map);
  sb_tiff_unmap = tiff_sb->register_callback(tiff_unmap);

  sb_tiff_name = rlbox::sandbox_str(tiff_sb, "Tiff Image");
  TIFF* tif = TIFFClientOpen("Tiff Image", mode, (thandle_t)context, tiff_read,
                             tiff_write, tiff_seek, tiff_close, tiff_get_size,
                             tiff_map, tiff_unmap);
  if (tif) {
    tif->tif_fd = (int)(intptr_t)context;
  }

  //return tif;
  //m_tif_ctx.reset(tiff_open(this, "r"));
  return !!m_tif_ctx;

}

bool CTiffContext::LoadFrameInfo(int32_t frame,
                                 int32_t* width,
                                 int32_t* height,
                                 int32_t* comps,
                                 int32_t* bpc,
                                 CFX_DIBAttribute* pAttribute) {
  // TODO: SANDBOX
  if (!TIFFSetDirectory(m_tif_ctx.get(), (uint16)frame))
    return false;

  uint32_t tif_width = 0;
  uint32_t tif_height = 0;
  uint16_t tif_comps = 0;
  uint16_t tif_bpc = 0;
  uint32_t tif_rps = 0;
  // TODO: SANDBOX
  TIFFGetField(m_tif_ctx.get(), TIFFTAG_IMAGEWIDTH, &tif_width);
  TIFFGetField(m_tif_ctx.get(), TIFFTAG_IMAGELENGTH, &tif_height);
  TIFFGetField(m_tif_ctx.get(), TIFFTAG_SAMPLESPERPIXEL, &tif_comps);
  TIFFGetField(m_tif_ctx.get(), TIFFTAG_BITSPERSAMPLE, &tif_bpc);
  TIFFGetField(m_tif_ctx.get(), TIFFTAG_ROWSPERSTRIP, &tif_rps);

  uint16_t tif_resunit = 0;
  // TODO:SANDBOX
  if (TIFFGetField(m_tif_ctx.get(), TIFFTAG_RESOLUTIONUNIT, &tif_resunit)) {
    pAttribute->m_wDPIUnit =
        static_cast<CFX_DIBAttribute::ResUnit>(tif_resunit - 1);
  } else {
    pAttribute->m_wDPIUnit = CFX_DIBAttribute::kResUnitInch;
  }

  float tif_xdpi = 0.0f;
  // TODO:SANDBOX
  TIFFGetField(m_tif_ctx.get(), TIFFTAG_XRESOLUTION, &tif_xdpi);
  if (tif_xdpi)
    pAttribute->m_nXDPI = static_cast<int32_t>(tif_xdpi + 0.5f);

  float tif_ydpi = 0.0f;
  // TODO:SANDBOX
  TIFFGetField(m_tif_ctx.get(), TIFFTAG_YRESOLUTION, &tif_ydpi);
  if (tif_ydpi)
    pAttribute->m_nYDPI = static_cast<int32_t>(tif_ydpi + 0.5f);

  FX_SAFE_INT32 checked_width = tif_width;
  FX_SAFE_INT32 checked_height = tif_height;
  if (!checked_width.IsValid() || !checked_height.IsValid())
    return false;

  *width = checked_width.ValueOrDie();
  *height = checked_height.ValueOrDie();
  *comps = tif_comps;
  *bpc = tif_bpc;
  if (tif_rps > tif_height) {
    tif_rps = tif_height;
    // TODO:SANDBOX
    TIFFSetField(m_tif_ctx.get(), TIFFTAG_ROWSPERSTRIP, tif_rps);
  }
  return true;
}

bool CTiffContext::IsSupport(const RetainPtr<CFX_DIBitmap>& pDIBitmap) const {
    // TODO:SANDBOX
  if (TIFFIsTiled(m_tif_ctx.get())) 
    return false;

  uint16_t photometric = 0;
    // TODO:SANDBOX

  if (!TIFFGetField(m_tif_ctx.get(), TIFFTAG_PHOTOMETRIC, &photometric))
    return false;

  switch (pDIBitmap->GetBPP()) {
    case 1:
    case 8:
      if (photometric != PHOTOMETRIC_PALETTE) {
        return false;
      }
      break;
    case 24:
      if (photometric != PHOTOMETRIC_RGB) {
        return false;
      }
      break;
    default:
      return false;
  }
  uint16_t planarconfig = 0;
    // TODO:SANDBOX

  if (!TIFFGetFieldDefaulted(m_tif_ctx.get(), TIFFTAG_PLANARCONFIG,
                             &planarconfig))
    return false;

  return planarconfig != PLANARCONFIG_SEPARATE;
}

void CTiffContext::SetPalette(const RetainPtr<CFX_DIBitmap>& pDIBitmap,
                              uint16_t bps) {
  uint16_t* red_orig = nullptr;
  uint16_t* green_orig = nullptr;
  uint16_t* blue_orig = nullptr;
    // TODO:SANDBOX

  TIFFGetField(m_tif_ctx.get(), TIFFTAG_COLORMAP, &red_orig, &green_orig,
               &blue_orig);
  for (int32_t i = pdfium::base::checked_cast<int32_t>((1L << bps) - 1); i >= 0;
       i--) {
#define CVT(x) ((uint16_t)((x) >> 8))
    red_orig[i] = CVT(red_orig[i]);
    green_orig[i] = CVT(green_orig[i]);
    blue_orig[i] = CVT(blue_orig[i]);
#undef CVT
  }
  int32_t len = 1 << bps;
  for (int32_t index = 0; index < len; index++) {
    uint32_t r = red_orig[index] & 0xFF;
    uint32_t g = green_orig[index] & 0xFF;
    uint32_t b = blue_orig[index] & 0xFF;
    uint32_t color = (uint32_t)b | ((uint32_t)g << 8) | ((uint32_t)r << 16) |
                     (((uint32)0xffL) << 24);
    pDIBitmap->SetPaletteArgb(index, color);
  }
}

bool CTiffContext::Decode1bppRGB(const RetainPtr<CFX_DIBitmap>& pDIBitmap,
                                 int32_t height,
                                 int32_t width,
                                 uint16_t bps,
                                 uint16_t spp) {
  if (pDIBitmap->GetBPP() != 1 || spp != 1 || bps != 1 ||
      !IsSupport(pDIBitmap)) {
    return false;
  }
  SetPalette(pDIBitmap, bps);
    // SANDBOXED
  int32_t size = static_cast<int32_t>(tiff_sb->invoke_sandbox_function(TIFFScanlineSize, m_tif_ctx).copy_and_verify([](int64_t ret){
      // size should not be less than 0 or overflow.
      if (ret < 0 || ret > 2147483647){
        return false;
      }
      return true;
  }));
  rlbox::tainted<uint8_t*, rlbox_sandbox_tiff> buf = tiff_sb->malloc_in_sandbox<uint8_t>(size);
  if (!buf) {
      // TODO:SANDBOX, what to do with errors?
    //TIFFError(TIFFFileName(m_tif_ctx.get()), "No space for scanline buffer");
    return false;
  }
  for (int32_t row = 0; row < height; row++) {
    uint8_t* bitMapbuffer = pDIBitmap->GetWritableScanline(row).data();
    // SANDBOXED
    // ret isn't used right here, so no need for copy verify
    tiff_sb->invoke_sandbox_function(TIFFReadScanline, m_tif_ctx, buf, row, 0);
    for (int32_t j = 0; j < size; j++) {
      bitMapbuffer[j] = buf[j].copy_and_verify([](uint8_t ret){
        // HOW DO WE VERIFY THIS?
        // bitmap values are already 0-255, no good way to verify?
        return true;
      });
    }
  }
  tiff_sb->free_in_sandbox(buf);
  return true;
}

bool CTiffContext::Decode8bppRGB(const RetainPtr<CFX_DIBitmap>& pDIBitmap,
                                 int32_t height,
                                 int32_t width,
                                 uint16_t bps,
                                 uint16_t spp) {
  if (pDIBitmap->GetBPP() != 8 || spp != 1 || (bps != 4 && bps != 8) ||
      !IsSupport(pDIBitmap)) {
    return false;
  }
  SetPalette(pDIBitmap, bps);
    // SANDBOXED
  int32_t size = static_cast<int32_t>(tiff_sb->invoke_sandbox_function(TIFFScanlineSize, m_tif_ctx).copy_and_verify([](int64_t ret){
      // size should not be less than 0 or overflow.
      if (ret < 0 || ret > 2147483647){
        return false;
      }
      return true;
  }));
  rlbox::tainted<uint8_t*, rlbox_sandbox_tiff> buf = tiff_sb->malloc_in_sandbox<uint8_t>(size);
  if (!buf) {
      // TODO:SANDBOX, what to do with errors?
    //TIFFError(TIFFFileName(m_tif_ctx.get()), "No space for scanline buffer");
    return false;
  }
  for (int32_t row = 0; row < height; row++) {
    uint8_t* bitMapbuffer = pDIBitmap->GetWritableScanline(row).data();
    // SANDBOXED
    tiff_sb->invoke_sandbox_function(TIFFReadScanline, m_tif_ctx, buf, row, 0);
    for (int32_t j = 0; j < size; j++) {
      uint8_t bval = buf[j].copy_and_verify([](uint8_t ret){
        // HOW DO WE VERIFY THIS?
        // bitmap values are already 0-255, no good way to verify?
        return true;
      });
      switch (bps) {
        case 4:
          bitMapbuffer[2 * j + 0] = (bval & 0xF0) >> 4;
          bitMapbuffer[2 * j + 1] = (bval & 0x0F) >> 0;
          break;
        case 8:
          bitMapbuffer[j] = bval;
          break;
      }
    }
  }
  //_TIFFfree(buf);
  tiff_sb->free_in_sandbox(buf);
  return true;
}

bool CTiffContext::Decode24bppRGB(const RetainPtr<CFX_DIBitmap>& pDIBitmap,
                                  int32_t height,
                                  int32_t width,
                                  uint16_t bps,
                                  uint16_t spp) {
  if (pDIBitmap->GetBPP() != 24 || !IsSupport(pDIBitmap))
    return false;
  // TODO:SANDBOX

  int32_t size = static_cast<int32_t>(tiff_sb->invoke_sandbox_function(TIFFScanlineSize, m_tif_ctx).copy_and_verify([](int64_t ret){
      // size should not be less than 0 or overflow.
      if (ret < 0 || ret > 2147483647){
        return false;
      }
      return true;
  }));
  rlbox::tainted<uint8_t*, rlbox_sandbox_tiff> buf = tiff_sb->malloc_in_sandbox<uint8_t>(size);
  if (!buf) {
    //TIFFError(TIFFFileName(m_tif_ctx.get()), "No space for scanline buffer");
    return false;
  }
  for (int32_t row = 0; row < height; row++) {
    uint8_t* bitMapbuffer = pDIBitmap->GetWritableScanline(row).data();
    tiff_sb->invoke_sandbox_function(TIFFReadScanline, m_tif_ctx, buf, row, 0);
    for (int32_t j = 0; j < size - 2; j += 3) {
      bitMapbuffer[j + 0] = buf[j + 2].copy_and_verify([](uint8_t ret){
            // HOW DO WE VERIFY THIS?
            // bitmap values are already 0-255, no good way to verify?
            return true;
          });
      bitMapbuffer[j + 1] = buf[j + 1].copy_and_verify([](uint8_t ret){
            // HOW DO WE VERIFY THIS?
            // bitmap values are already 0-255, no good way to verify?
            return true;
          });
      bitMapbuffer[j + 2] = buf[j].copy_and_verify([](uint8_t ret){
            // HOW DO WE VERIFY THIS?
            // bitmap values are already 0-255, no good way to verify?
            return true;
          });
    }
  }
  //_TIFFfree(buf);
  tiff_sb->free_in_sandbox(buf);
  return true;
}

bool CTiffContext::Decode(const RetainPtr<CFX_DIBitmap>& pDIBitmap) {
  uint32_t img_width = pDIBitmap->GetWidth();
  uint32_t img_height = pDIBitmap->GetHeight();
  uint32_t width = 0;
  uint32_t height = 0;
  // TODO:SANDBOX
  rlbox::tainted<uint32_t*, rlbox_sandbox_tiff> sb_width = tiff_sb->malloc_in_sandbox<uint32_t>();
  rlbox::tainted<uint32_t*, rlbox_sandbox_tiff> sb_height = tiff_sb->malloc_in_sandbox<uint32_t>();
  tiff_sb->invoke_sandbox_function(TIFFGetField<uint32_t>, TIFFTAG_IMAGEWIDTH, sb_width);
  tiff_sb->invoke_sandbox_function(TIFFGetField<uint32_t>, TIFFTAG_IMAGELENGTH, sb_height);
  // okay for now, checked in next if statement
  width = (*t_width).copy_and_verify([](uint32_t ret){return true;});
  height = (*t_height).copy_and_verify([](uint32_t ret){return true;});
  tiff_sb->free_in_sandbox(sb_width);
  tiff_sb->free_in_sandbox(sb_height);
  if (img_width != width || img_height != height)
    return false;

  if (pDIBitmap->GetBPP() == 32) {
    uint16_t rotation = ORIENTATION_TOPLEFT;
    TIFFGetField(m_tif_ctx.get(), TIFFTAG_ORIENTATION, &rotation);
    if (TIFFReadRGBAImageOriented(m_tif_ctx.get(), img_width, img_height,
                                  (uint32*)pDIBitmap->GetBuffer(), rotation,
                                  1)) {
      for (uint32_t row = 0; row < img_height; row++) {
        uint8_t* row_buf = pDIBitmap->GetWritableScanline(row).data();
        TiffBGRA2RGBA(row_buf, img_width, 4);
      }
      return true;
    }
  }
  // TODO:SANDBOX
  rlbox::tainted<uint16_t*, rlbox_sandbox_tiff> sb_spp = m_tif_sbx->malloc_in_sandbox<uint16_t>();
  rlbox::tainted<uint16_t*, rlbox_sandbox_tiff> sb_bps = m_tif_sbx->malloc_in_sandbox<uint16_t>();
  tiff_sb->invoke_sandbox_function(TIFFGetField<uint16_t>, TIFFTAG_SAMPLESPERPIXEL, sb_spp);
  tiff_sb->invoke_sandbox_function(TIFFGetField<uint16_t>, TIFFTAG_BITSPERSAMPLE, sb_bps);
  // okay for now, bc checked below - safevalue or die
  uint16_t spp = (*sb_spp).copy_and_verify([](uint32_t ret){return true;});
  uint16_t bps = (*sb_bps).copy_and_verify([](uint32_t ret){return true;});
  m_tif_sbx->free_in_sandbox(sb_spp);
  m_tif_sbx->free_in_sandbox(sb_bps);
  FX_SAFE_UINT32 safe_bpp = bps;
  safe_bpp *= spp;
  if (!safe_bpp.IsValid())
    return false;
  uint32_t bpp = safe_bpp.ValueOrDie();
  if (bpp == 1)
    return Decode1bppRGB(pDIBitmap, height, width, bps, spp);
  if (bpp <= 8)
    return Decode8bppRGB(pDIBitmap, height, width, bps, spp);
  if (bpp <= 24)
    return Decode24bppRGB(pDIBitmap, height, width, bps, spp);
  return false;
}

namespace fxcodec {

// static
std::unique_ptr<ProgressiveDecoderIface::Context> TiffDecoder::CreateDecoder(
    const RetainPtr<IFX_SeekableReadStream>& file_ptr) {
  auto pDecoder = std::make_unique<CTiffContext>();
  if (!pDecoder->InitDecoder(file_ptr))
    return nullptr;

  return pDecoder;
}

// static
bool TiffDecoder::LoadFrameInfo(ProgressiveDecoderIface::Context* pContext,
                                int32_t frame,
                                int32_t* width,
                                int32_t* height,
                                int32_t* comps,
                                int32_t* bpc,
                                CFX_DIBAttribute* pAttribute) {
  DCHECK(pAttribute);

  auto* ctx = static_cast<CTiffContext*>(pContext);
  return ctx->LoadFrameInfo(frame, width, height, comps, bpc, pAttribute);
}

// static
bool TiffDecoder::Decode(ProgressiveDecoderIface::Context* pContext,
                         const RetainPtr<CFX_DIBitmap>& pDIBitmap) {
  auto* ctx = static_cast<CTiffContext*>(pContext);
  return ctx->Decode(pDIBitmap);
}

}  // namespace fxcodec
