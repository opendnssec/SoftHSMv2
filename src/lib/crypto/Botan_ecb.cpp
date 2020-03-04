/*
* ECB Mode
* (C) 1999-2009,2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/version.h>

// ECB cipher mode was dropped in Botan 2.0.0
// so including this code in SoftHSM for continued support
// for e.g. CKA_VALUE_CHECK

#include "Botan_ecb.h"

namespace Botan {

ECB_Mode::ECB_Mode(BlockCipher* cipher, bool with_pkcs7_padding) :
   m_cipher(cipher),
   m_with_pkcs7_padding(with_pkcs7_padding)
   {
   }

void ECB_Mode::clear()
   {
   m_cipher->clear();
   }

void ECB_Mode::reset()
   {
   // no msg state here
   return;
   }

std::string ECB_Mode::name() const
   {
   std::string name = cipher().name();
   name += "/ECB/";
   if(m_with_pkcs7_padding)
      name += "PKCS7";
   else
      name += "NoPadding";
   return name;
   }

size_t ECB_Mode::update_granularity() const
   {
   return cipher().parallel_bytes();
   }

Key_Length_Specification ECB_Mode::key_spec() const
   {
   return cipher().key_spec();
   }

size_t ECB_Mode::default_nonce_length() const
   {
   return 0;
   }

bool ECB_Mode::valid_nonce_length(size_t n) const
   {
   return (n == 0);
   }

void ECB_Mode::key_schedule(const byte key[], size_t length)
   {
   m_cipher->set_key(key, length);
   }

void ECB_Mode::start_msg(const byte[], size_t nonce_len)
   {
   if(nonce_len != 0)
      throw Invalid_IV_Length(name(), nonce_len);
   }

size_t ECB_Encryption::minimum_final_size() const
   {
   return 0;
   }

namespace {

inline size_t round_up(size_t n, size_t align_to)
   {
   BOTAN_ASSERT(align_to != 0, "align_to must not be 0");

   if(n % align_to)
      n += align_to - (n % align_to);
   return n;
   }

}

size_t ECB_Encryption::output_length(size_t input_length) const
   {
   if(input_length == 0)
      return cipher().block_size();
   else
      return round_up(input_length, cipher().block_size());
   }

size_t ECB_Encryption::process(uint8_t buf[], size_t sz)
   {
   const size_t BS = cipher().block_size();
   BOTAN_ASSERT(sz % BS == 0, "ECB input is full blocks");
   const size_t blocks = sz / BS;
   cipher().encrypt_n(buf, buf, blocks);
   return sz;
   }

void ECB_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;

   const size_t BS = cipher().block_size();

   const size_t bytes_in_final_block = sz % BS;

   if(with_pkcs7_padding())
      {
      const uint8_t pad_value = static_cast<uint8_t>(BS - bytes_in_final_block);

      for(size_t i = 0; i != pad_value; ++i)
         buffer.push_back(pad_value);
      }

   if(buffer.size() % BS)
      throw Encoding_Error("Did not pad to full block size in " + name());

   update(buffer, offset);
   }

size_t ECB_Decryption::output_length(size_t input_length) const
   {
   return input_length;
   }

size_t ECB_Decryption::minimum_final_size() const
   {
   return cipher().block_size();
   }

size_t ECB_Decryption::process(uint8_t buf[], size_t sz)
   {
   const size_t BS = cipher().block_size();
   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;
   cipher().decrypt_n(buf, buf, blocks);
   return sz;
   }

namespace {

size_t pkcs7_unpad(const byte block[], size_t size)
   {
   size_t position = block[size-1];

   if(position > size)
      throw Decoding_Error("Bad PKCS7 padding");

   for(size_t j = size-position; j != size-1; ++j)
      if(block[j] != position)
         throw Decoding_Error("Bad PKCS7 padding");

   return (size-position);
   }

}

void ECB_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;

   const size_t BS = cipher().block_size();

   if(sz == 0 || sz % BS)
      throw Decoding_Error(name() + ": Ciphertext not a multiple of block size");

   update(buffer, offset);

   if(with_pkcs7_padding())
      {
      const size_t pad_bytes = BS - pkcs7_unpad(&buffer[buffer.size()-BS], BS);
      buffer.resize(buffer.size() - pad_bytes); // remove padding
      }
   }

}
