using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.InteropServices;

/*
 https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 */
namespace PEDumperCompact
{
    class Program
    {
        const short MAGIC32 = 0x010b, MAGIC64 = 0x020b;
        const int sizeofPEMagic = 4, sizeofCoffHeader = 20, sizeofNamePointer = 4;
        private static byte[] buffer;
        private static MemoryStream _ms;
        private static short NumberOfSections, SizeOfOptionalHeader, Magic;
        private static _IMAGE_DATA_DIRECTORY ExportTable;
        private static _IMAGE_SECTION_HEADER[] sectionHeader;
        private static int _peMagicOffset, DllName, NumberOfNames, AddressOfNames, NumberOfRvaAndSizes, exportSectionOrdinal = -1;
        private static bool isPe32 => Magic == MAGIC32;
        private static bool isPe32Plus => Magic == MAGIC64;
        private static int _optionHeaderOffset => _peMagicOffset + sizeofPEMagic + sizeofCoffHeader; //is this always a 256 boundary
        struct _IMAGE_DATA_DIRECTORY { public int VirtualAddress, Size; }
        struct _IMAGE_SECTION_HEADER { public int VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData; }

        static void Main(string[] args)
        {
            buffer = File.ReadAllBytes(@"C:\windows\system32\user32.dll");

            using (_ms = new MemoryStream(buffer, false))
            {
                ReadDosHeader(); AssertPeHeader();
                ReadCoffHeader(); ReadOptionalHeader();
                AssertOptionHeaderMagic(); ReadSections();
                ReadExportDirectory(); ReadExportNames();
            }
        }

        static void AssertPeHeader()
        {
            const uint PEMagicNumber = 0x00004550;
            var peValue = BitConverter.ToUInt32(buffer, _peMagicOffset);
            if (PEMagicNumber != peValue) throw new Exception("PE");
        }

        static void ReadDosHeader()
        {
            int skipABunchOfFields = 2 * 30;

            _ms.Seek(skipABunchOfFields, SeekOrigin.Begin);

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                _peMagicOffset = rdr.ReadInt32();
            }

        }

        static void ReadCoffHeader()
        {
            _ms.Seek(_peMagicOffset + sizeofPEMagic, SeekOrigin.Begin);

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                rdr.ReadInt16();
                NumberOfSections = rdr.ReadInt16();
                rdr.ReadBytes(12);
                SizeOfOptionalHeader = rdr.ReadInt16();
            }

        }

        static void ReadOptionalHeader()
        {
            _ms.Seek(_optionHeaderOffset, SeekOrigin.Begin);

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                Magic = rdr.ReadInt16();
                if (isPe32) rdr.ReadBytes(94);
                else if (isPe32Plus) rdr.ReadBytes(110);
                ExportTable.VirtualAddress = rdr.ReadInt32();
                ExportTable.Size = rdr.ReadInt32();
            }
        }

        static void AssertOptionHeaderMagic()
        {
            if (!(isPe32 || isPe32Plus)) throw new Exception("option header magic");
        }

        static void ReadSections()
        {
            _ms.Seek(_optionHeaderOffset + SizeOfOptionalHeader, SeekOrigin.Begin);

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                sectionHeader = new _IMAGE_SECTION_HEADER[NumberOfSections];

                for (int sectionIdx = 0; sectionIdx < NumberOfSections; sectionIdx++)
                {
                    rdr.ReadBytes(8);
                    sectionHeader[sectionIdx].VirtualSize = rdr.ReadInt32();
                    sectionHeader[sectionIdx].VirtualAddress = rdr.ReadInt32();
                    sectionHeader[sectionIdx].SizeOfRawData = rdr.ReadInt32();
                    sectionHeader[sectionIdx].PointerToRawData = rdr.ReadInt32();
                    rdr.ReadBytes(16);
                }
            }


        }

        static void ReadExportDirectory()
        {
            /*
             * https://blog.kowalczyk.info/articles/pefileformat.html
             * A directory VirtualAddress lands within the VirtualAddress range
             * of the section it belongs
             * section.VirtualAddress <= directory.VirtualAddress <= (section.VirtualAddress + section.SizeOfRawData)
             * or efficiently,
             * directory.VirtualAddress >= section.VirtualAddress  && directory.VirtualAddress < (section.VirtualAddress + section.SizeOfRawData)
             */
            for (int i = 0; i < sectionHeader.Length; i++)
            {
                int StartOfSection = sectionHeader[i].VirtualAddress;
                int EndOfSection = sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData;

                if (ExportTable.VirtualAddress >= StartOfSection
                    && ExportTable.VirtualAddress < EndOfSection)
                { exportSectionOrdinal = i; break; }
            }

            if (exportSectionOrdinal > -1)
            {
                var edataSection = sectionHeader[exportSectionOrdinal];
                int eOffset = edataSection.PointerToRawData + (ExportTable.VirtualAddress - edataSection.VirtualAddress);

                _ms.Seek(eOffset, SeekOrigin.Begin);

                using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
                {
                    rdr.ReadBytes(12);
                    DllName = rdr.ReadInt32();
                    rdr.ReadBytes(8);
                    NumberOfNames = rdr.ReadInt32();
                    rdr.ReadBytes(4);
                    AddressOfNames = rdr.ReadInt32();
                }
            }
        }

        static void ReadExportNames()
        {
            if (exportSectionOrdinal == -1) return;
            var edataSection = sectionHeader[exportSectionOrdinal];

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                var mPointer = edataSection.PointerToRawData + (DllName - edataSection.VirtualAddress);

                _ms.Seek(mPointer, SeekOrigin.Begin);

                var moduleName = rdr.ReadAsciiString();

                Console.WriteLine($"Module is {moduleName} with {NumberOfNames} exports.\n");

                for (int i = 0; i < NumberOfNames; i++)
                {
                    int indexIntoAddressTable = sizeofNamePointer * i;
                    var pName = BitConverter.ToUInt32(buffer, edataSection.PointerToRawData + ((AddressOfNames + indexIntoAddressTable) - edataSection.VirtualAddress));
                    var nameOffset = edataSection.PointerToRawData + (pName - edataSection.VirtualAddress);
                    _ms.Seek(nameOffset, SeekOrigin.Begin);
                    var name = rdr.ReadAsciiString();
                    Console.WriteLine(name);
                }
            }

        }

    }

    static class BinaryReaderExtensions
    {
        public static string ReadAsciiString(this BinaryReader rdr)
        {
            var sb = new System.Text.StringBuilder(256);
            while (rdr.PeekChar() != '\0') sb.Append(rdr.ReadChar());
            return sb.ToString();
        }
    }
}
