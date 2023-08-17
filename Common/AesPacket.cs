using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Common
{
    public class AesPacket
    {
        public byte[] Key { get; set; }
        public byte[] iv { get; set; }
    }
}
