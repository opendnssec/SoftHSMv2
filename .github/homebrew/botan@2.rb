# Copied from Homebrew/homebrew-core at commit c0c9ff1d10f9b975f2d3fc2385c042a579749815
# (Formula/b/botan@2.rb) with its deprecate!/disable! lines removed, so that it
# still installs after Homebrew removes botan@2. Used by .github/workflows/ci.yml.
#
# BSD 2-Clause License
#
# Copyright (c) 2009-present, Homebrew contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

class BotanAT2 < Formula
  desc "Cryptographic algorithms and formats library in C++"
  homepage "https://botan.randombit.net/"
  url "https://botan.randombit.net/releases/Botan-2.19.5.tar.xz"
  sha256 "dfeea0e0a6f26d6724c4af01da9a7b88487adb2d81ba7c72fcaf52db522c9ad4"
  license "BSD-2-Clause"

  bottle do
    rebuild 2
    sha256 arm64_tahoe:   "dd852d6fe3cc65e68fe497d5582c7f3dbaa4c2afced2acea3a9b0f412042bd82"
    sha256 arm64_sequoia: "3b52c4abedf724426066b343384e553b586d7a3d69e437a85839ad1adde27868"
    sha256 arm64_sonoma:  "dc8d1646e46dab1be1f4f53b46f2e111b92610998ec700579c702abe3bee9baf"
    sha256 sonoma:        "534d9389e8a96ed9c171e1c457c931f70783c94515ff502c6fd876c369666f09"
    sha256 arm64_linux:   "faf67b146845389405939b4803884a521fd4210e441b078fea28cdeca78e78ac"
    sha256 x86_64_linux:  "a4d30c4277c84df5b6a0e51b82e049df3bbe90204151143bf68bf214f44cbd86"
  end

  keg_only :versioned_formula

  # Botan2 is currently scheduled to reach end of life at the end of 2024
  # Ref: https://botan.randombit.net/#releases

  depends_on "pkgconf" => :build
  depends_on "python@3.14"
  depends_on "sqlite"

  uses_from_macos "bzip2"
  uses_from_macos "zlib"

  def install
    ENV.cxx11

    args = %W[
      --prefix=#{prefix}
      --docdir=share/doc
      --with-zlib
      --with-bzip2
      --with-sqlite3
    ]

    system python3, "configure.py", *args
    system "make", "install"
  end

  test do
    (testpath/"test.txt").write "Homebrew"
    (testpath/"testout.txt").write shell_output("#{bin}/botan base64_enc test.txt")
    assert_match "Homebrew", shell_output("#{bin}/botan base64_dec testout.txt")
  end
end
