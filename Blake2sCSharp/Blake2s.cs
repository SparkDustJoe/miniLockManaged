// Originally Written in 2012 by Christian Winnerlein  <codesinchaos@gmail.com>
// Rewritten Fall 2014 (for the Blake2s flavor instead of the Blake2b flavor) 
//   by Dustin Sparks <sparkdustjoe@gmail.com>

// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.

// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
/*
  Based on BlakeSharp
  by Dominik Reichl <dominik.reichl@t-online.de>
  Web: http://www.dominik-reichl.de/
  If you're using this class, it would be nice if you'd mention
  me somewhere in the documentation of your program, but it's
  not required.

  BLAKE was designed by Jean-Philippe Aumasson, Luca Henzen,
  Willi Meier and Raphael C.-W. Phan.
  BlakeSharp was derived from the reference C implementation.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Blake2sCSharp
{
    public static class Blake2S
    {
        public static Hasher Create()
        {
            return Create(new Blake2sConfig());
        }

        public static Hasher Create(Blake2sConfig config)
        {
            return new Blake2sHasher(config);
        }

        public static byte[] ComputeHash(byte[] data, int start, int count)
        {
            return ComputeHash(data, start, count, null);
        }

        public static byte[] ComputeHash(byte[] data)
        {
            return ComputeHash(data, 0, data.Length, null);
        }

        public static byte[] ComputeHash(byte[] data, Blake2sConfig config)
        {
            return ComputeHash(data, 0, data.Length, config);
        }

        public static byte[] ComputeHash(byte[] data, int start, int count, Blake2sConfig config)
        {
            var hasher = Create(config);
            hasher.Update(data, start, count);
            return hasher.Finish();
        }
    }

}
