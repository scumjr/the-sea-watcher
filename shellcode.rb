#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# in this exemple we can write a shellcode using a C function
#

require 'metasm'

# load and decode the file
sc = Metasm::Shellcode.new(Metasm::Ia32.new)
sc.parse <<EOS
call walk_memory
ret
EOS

source = File.read(ARGV[0])

cp = sc.cpu.new_cparser
cp.parse source
asm = sc.cpu.new_ccompiler(cp, sc).compile

sc.parse asm
sc.assemble

sc.encode_file ARGV[1]
