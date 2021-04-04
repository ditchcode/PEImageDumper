using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.InteropServices;

/*
 https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 */
namespace PEDumper
{
    class Program
    {
        const short MAGIC32 = 0x010b;
        const short MAGIC64 = 0x020b;
        const int sizeofPEMagic = 4;
        const int sizeofCoffHeader = 20;

        private static byte[] buffer;
        private static MemoryStream _ms;
        private static _IMAGE_DOS_HEADER dosHeader;
        private static _IMAGE_FILE_HEADER coffHeader;
        private static _IMAGE_OPTIONAL_HEADER optionalHeader;
        private static _IMAGE_SECTION_HEADER[] sectionHeader;
        private static _IMAGE_EXPORT_DIRECTORY exportDirectory;
        private static int exportSectionOrdinal = -1;

        private static bool isPe32 => optionalHeader.Magic == MAGIC32;
        private static bool isPe32Plus => optionalHeader.Magic == MAGIC64;

        private static int _peMagicOffset => dosHeader.e_lfanew;

        private static int _optionHeaderOffset => _peMagicOffset + sizeofPEMagic + sizeofCoffHeader; //is this always a 256 boundary

        private static int _optionHeaderSize => coffHeader.SizeOfOptionalHeader;


        static void Main(string[] args)
        {
            buffer = File.ReadAllBytes(@"c:\temp\kernel32.dll");

            using (_ms = new MemoryStream(buffer, false))
            {
                ReadDosHeader();

                AssertPeHeader();

                ReadCoffHeader();

                ReadOptionalHeader();

                AssertOptionHeaderMagic();

                ReadSections();

                ReadExportDirectory();

                ReadExportNames();
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
            _ms.Seek(0, SeekOrigin.Begin);
            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                dosHeader.e_magic = rdr.ReadInt16();
                dosHeader.e_cblp = rdr.ReadInt16();
                dosHeader.e_cp = rdr.ReadInt16();
                dosHeader.e_crlc = rdr.ReadInt16();
                dosHeader.e_cparhdr = rdr.ReadInt16();
                dosHeader.e_minalloc = rdr.ReadInt16();
                dosHeader.e_maxalloc = rdr.ReadInt16();
                dosHeader.e_ss = rdr.ReadInt16();
                dosHeader.e_sp = rdr.ReadInt16();
                dosHeader.e_csum = rdr.ReadInt16();
                dosHeader.e_ip = rdr.ReadInt16();
                dosHeader.e_cs = rdr.ReadInt16();
                dosHeader.e_lfarlc = rdr.ReadInt16();
                dosHeader.e_ovno = rdr.ReadInt16();
                dosHeader.e_res_0 = rdr.ReadInt16();
                dosHeader.e_res_1 = rdr.ReadInt16();
                dosHeader.e_res_2 = rdr.ReadInt16();
                dosHeader.e_res_3 = rdr.ReadInt16();
                dosHeader.e_oemid = rdr.ReadInt16();
                dosHeader.e_oeminfo = rdr.ReadInt16();
                dosHeader.e_res2_0 = rdr.ReadInt16();
                dosHeader.e_res2_1 = rdr.ReadInt16();
                dosHeader.e_res2_2 = rdr.ReadInt16();
                dosHeader.e_res2_3 = rdr.ReadInt16();
                dosHeader.e_res2_4 = rdr.ReadInt16();
                dosHeader.e_res2_5 = rdr.ReadInt16();
                dosHeader.e_res2_6 = rdr.ReadInt16();
                dosHeader.e_res2_7 = rdr.ReadInt16();
                dosHeader.e_res2_8 = rdr.ReadInt16();
                dosHeader.e_res2_9 = rdr.ReadInt16();
                dosHeader.e_lfanew = rdr.ReadInt32();
            }

        }

        static void ReadCoffHeader()
        {
            _ms.Seek(_peMagicOffset + sizeofPEMagic, SeekOrigin.Begin);

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                coffHeader.Machine = rdr.ReadInt16();
                coffHeader.NumberOfSections = rdr.ReadInt16();
                coffHeader.TimeDateStamp = rdr.ReadInt32();
                coffHeader.PointerToSymbolTable = rdr.ReadInt32();
                coffHeader.NumberOfSymbols = rdr.ReadInt32();
                coffHeader.SizeOfOptionalHeader = rdr.ReadInt16();
                coffHeader.Characteristics = rdr.ReadInt16();

            }

        }

        static void ReadOptionalHeader()
        {


            _ms.Seek(_optionHeaderOffset, SeekOrigin.Begin);

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                optionalHeader.Magic = rdr.ReadInt16();

                optionalHeader.MajorLinkerVersion = rdr.ReadByte();
                optionalHeader.MinorLinkerVersion = rdr.ReadByte();
                optionalHeader.SizeOfCode = rdr.ReadInt32();
                optionalHeader.SizeOfInitializedData = rdr.ReadInt32();
                optionalHeader.SizeOfUninitializedData = rdr.ReadInt32();
                optionalHeader.AddressOfEntryPoint = rdr.ReadInt32();
                optionalHeader.BaseOfCode = rdr.ReadInt32();

                if (isPe32)
                {
                    optionalHeader.BaseOfData = rdr.ReadInt32();
                    optionalHeader.ImageBase = rdr.ReadInt32();
                }
                else if (isPe32Plus)
                {
                    optionalHeader.ImageBase = rdr.ReadInt64();
                }

                optionalHeader.SectionAlignment = rdr.ReadInt32();
                optionalHeader.FileAlignment = rdr.ReadInt32();
                optionalHeader.MajorOperatingSystemVersion = rdr.ReadInt16();
                optionalHeader.MinorOperatingSystemVersion = rdr.ReadInt16();
                optionalHeader.MajorImageVersion = rdr.ReadInt16();
                optionalHeader.MinorImageVersion = rdr.ReadInt16();
                optionalHeader.MajorSubsystemVersion = rdr.ReadInt16();
                optionalHeader.MinorSubsystemVersion = rdr.ReadInt16();
                optionalHeader.Win32VersionValue = rdr.ReadInt32();
                optionalHeader.SizeOfImage = rdr.ReadInt32();
                optionalHeader.SizeOfHeaders = rdr.ReadInt32();
                optionalHeader.CheckSum = rdr.ReadInt32();
                optionalHeader.Subsystem = rdr.ReadInt16();
                optionalHeader.DllCharacteristics = rdr.ReadInt16();

                if (isPe32)
                {
                    optionalHeader.SizeOfStackReserve = rdr.ReadInt32();
                    optionalHeader.SizeOfStackCommit = rdr.ReadInt32();
                    optionalHeader.SizeOfHeapReserve = rdr.ReadInt32();
                    optionalHeader.SizeOfHeapCommit = rdr.ReadInt32();
                }
                else if (isPe32Plus)
                {
                    optionalHeader.SizeOfStackReserve = rdr.ReadInt64();
                    optionalHeader.SizeOfStackCommit = rdr.ReadInt64();
                    optionalHeader.SizeOfHeapReserve = rdr.ReadInt64();
                    optionalHeader.SizeOfHeapCommit = rdr.ReadInt64();
                }

                optionalHeader.LoaderFlags = rdr.ReadInt32();
                optionalHeader.NumberOfRvaAndSizes = rdr.ReadInt32();

                var directoryIdx = optionalHeader.NumberOfRvaAndSizes;

                if (directoryIdx-- > 0)
                {
                    optionalHeader.ExportTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.ExportTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.ImportTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.ImportTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.ResourceTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.ResourceTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.ExceptionTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.ExceptionTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.CertificateTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.CertificateTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.BaseRelocationTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.BaseRelocationTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.Debug.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.Debug.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.Architecture.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.Architecture.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.GlobalPtr.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.GlobalPtr.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.TLSTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.TLSTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.LoadConfigTable.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.LoadConfigTable.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.BoundImport.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.BoundImport.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.IAT.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.IAT.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.DelayImportDescriptor.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.DelayImportDescriptor.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.CLRRuntimeHeader.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.CLRRuntimeHeader.Size = rdr.ReadInt32();
                }
                if (directoryIdx-- > 0)
                {
                    optionalHeader.Reserved.VirtualAddress = rdr.ReadInt32();
                    optionalHeader.Reserved.Size = rdr.ReadInt32();
                }
            }

        }

        static void AssertOptionHeaderMagic()
        {
            if (!(isPe32 || isPe32Plus)) throw new Exception("option header magic");
        }

        static void ReadSections()
        {
            _ms.Seek(_optionHeaderOffset + _optionHeaderSize, SeekOrigin.Begin);

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                sectionHeader = new _IMAGE_SECTION_HEADER[coffHeader.NumberOfSections];

                for (int sectionIdx = 0; sectionIdx < coffHeader.NumberOfSections; sectionIdx++)
                {
                    sectionHeader[sectionIdx].Name_0 = rdr.ReadByte();
                    sectionHeader[sectionIdx].Name_1 = rdr.ReadByte();
                    sectionHeader[sectionIdx].Name_2 = rdr.ReadByte();
                    sectionHeader[sectionIdx].Name_3 = rdr.ReadByte();
                    sectionHeader[sectionIdx].Name_4 = rdr.ReadByte();
                    sectionHeader[sectionIdx].Name_5 = rdr.ReadByte();
                    sectionHeader[sectionIdx].Name_6 = rdr.ReadByte();
                    sectionHeader[sectionIdx].Name_7 = rdr.ReadByte();

                    sectionHeader[sectionIdx].VirtualSize = rdr.ReadInt32();
                    sectionHeader[sectionIdx].VirtualAddress = rdr.ReadInt32();
                    sectionHeader[sectionIdx].SizeOfRawData = rdr.ReadInt32();
                    sectionHeader[sectionIdx].PointerToRawData = rdr.ReadInt32();
                    sectionHeader[sectionIdx].PointerToRelocations = rdr.ReadInt32();
                    sectionHeader[sectionIdx].PointerToLinenumbers = rdr.ReadInt32();

                    sectionHeader[sectionIdx].NumberOfRelocations = rdr.ReadInt16();
                    sectionHeader[sectionIdx].NumberOfLinenumbers = rdr.ReadInt16();

                    sectionHeader[sectionIdx].Characteristics = rdr.ReadInt32();
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
                if (optionalHeader.ExportTable.VirtualAddress >= sectionHeader[i].VirtualAddress
                            && optionalHeader.ExportTable.VirtualAddress < (sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData))
                {
                    exportSectionOrdinal = i;
                    break;
                }

            }


            if (exportSectionOrdinal > -1)
            {
                var edataSection = sectionHeader[exportSectionOrdinal];

                int eOffset = Convert.ToInt32(edataSection.PointerToRawData)
                    + (Convert.ToInt32(optionalHeader.ExportTable.VirtualAddress) - Convert.ToInt32(edataSection.VirtualAddress));

                _ms.Seek(eOffset, SeekOrigin.Begin);
                using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
                {

                    exportDirectory.Characteristics = rdr.ReadInt32();
                    exportDirectory.TimeDateStamp = rdr.ReadInt32();
                    exportDirectory.MajorVersion = rdr.ReadInt16();
                    exportDirectory.MinorVersion = rdr.ReadInt16();
                    exportDirectory.Name = rdr.ReadInt32();
                    exportDirectory.Base = rdr.ReadInt32();
                    exportDirectory.NumberOfFunctions = rdr.ReadInt32();
                    exportDirectory.NumberOfNames = rdr.ReadInt32();
                    exportDirectory.AddressOfFunctions = rdr.ReadInt32();
                    exportDirectory.AddressOfNames = rdr.ReadInt32();
                    exportDirectory.AddressOfNameOrdinals = rdr.ReadInt32();
                }


            }

        }

        static void ReadExportNames()
        {
            if (exportSectionOrdinal == -1) return;

            var edataSection = sectionHeader[exportSectionOrdinal];

            using (var rdr = new BinaryReader(_ms, System.Text.Encoding.ASCII, true))
            {
                var mPointer = edataSection.PointerToRawData + (exportDirectory.Name - edataSection.VirtualAddress);

                _ms.Seek(mPointer, SeekOrigin.Begin);

                var moduleName = rdr.ReadAsciiString();

                Console.WriteLine($"Module is {moduleName} with {exportDirectory.NumberOfNames} exports.\n");

                for (int i = 0; i < exportDirectory.NumberOfNames; i++)
                {
                    var pointer = BitConverter.ToUInt32(buffer, edataSection.PointerToRawData + ((exportDirectory.AddressOfNames + (4 * i)) - edataSection.VirtualAddress));

                    var nameOffset = edataSection.PointerToRawData + (pointer - edataSection.VirtualAddress);

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

    struct _IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public short e_magic;                     // Magic number
        public short e_cblp;                      // Bytes on last page of file
        public short e_cp;                        // Pages in file
        public short e_crlc;                      // Relocations
        public short e_cparhdr;                   // Size of header in paragraphs
        public short e_minalloc;                  // Minimum extra paragraphs needed
        public short e_maxalloc;                  // Maximum extra paragraphs needed
        public short e_ss;                        // Initial (relative) SS value
        public short e_sp;                        // Initial SP value
        public short e_csum;                      // Checksum
        public short e_ip;                        // Initial IP value
        public short e_cs;                        // Initial (relative) CS value
        public short e_lfarlc;                    // File address of relocation table
        public short e_ovno;                      // Overlay number
        public short e_res_0;                    // Reserved words
        public short e_res_1;                    // Reserved words
        public short e_res_2;                    // Reserved words
        public short e_res_3;                    // Reserved words
        public short e_oemid;                     // OEM identifier (for e_oeminfo)
        public short e_oeminfo;                   // OEM information; e_oemid specific
        public short e_res2_0;                  // Reserved words
        public short e_res2_1;                  // Reserved words
        public short e_res2_2;                  // Reserved words
        public short e_res2_3;                  // Reserved words
        public short e_res2_4;                  // Reserved words
        public short e_res2_5;                  // Reserved words
        public short e_res2_6;                  // Reserved words
        public short e_res2_7;                  // Reserved words
        public short e_res2_8;                  // Reserved words
        public short e_res2_9;                  // Reserved words
        public int e_lfanew;                    // File address of new exe header
    }

    struct _IMAGE_FILE_HEADER
    {
        public short Machine;
        public short NumberOfSections;
        public int TimeDateStamp;
        public int PointerToSymbolTable;
        public int NumberOfSymbols;
        public short SizeOfOptionalHeader;
        public short Characteristics;
    }

    struct _IMAGE_DATA_DIRECTORY
    {
        public int VirtualAddress;
        public int Size;
    }

    struct _IMAGE_OPTIONAL_HEADER
    {
        //
        // Standard fields.
        //

        public short Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public int SizeOfCode;
        public int SizeOfInitializedData;
        public int SizeOfUninitializedData;
        public int AddressOfEntryPoint;
        public int BaseOfCode;
        public int BaseOfData;

        //
        // NT additional fields.
        //

        public long ImageBase;
        public int SectionAlignment;
        public int FileAlignment;
        public short MajorOperatingSystemVersion;
        public short MinorOperatingSystemVersion;
        public short MajorImageVersion;
        public short MinorImageVersion;
        public short MajorSubsystemVersion;
        public short MinorSubsystemVersion;
        public int Win32VersionValue;
        public int SizeOfImage;
        public int SizeOfHeaders;
        public int CheckSum;
        public short Subsystem;
        public short DllCharacteristics;
        public long SizeOfStackReserve;
        public long SizeOfStackCommit;
        public long SizeOfHeapReserve;
        public long SizeOfHeapCommit;
        public long LoaderFlags;
        public int NumberOfRvaAndSizes;
        public _IMAGE_DATA_DIRECTORY ExportTable;
        public _IMAGE_DATA_DIRECTORY ImportTable;
        public _IMAGE_DATA_DIRECTORY ResourceTable;
        public _IMAGE_DATA_DIRECTORY ExceptionTable;
        public _IMAGE_DATA_DIRECTORY CertificateTable;
        public _IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public _IMAGE_DATA_DIRECTORY Debug;
        public _IMAGE_DATA_DIRECTORY Architecture;
        public _IMAGE_DATA_DIRECTORY GlobalPtr;
        public _IMAGE_DATA_DIRECTORY TLSTable;
        public _IMAGE_DATA_DIRECTORY LoadConfigTable;
        public _IMAGE_DATA_DIRECTORY BoundImport;
        public _IMAGE_DATA_DIRECTORY IAT;
        public _IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public _IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public _IMAGE_DATA_DIRECTORY Reserved;
    }


    struct _IMAGE_SECTION_HEADER
    {
        public byte Name_0;
        public byte Name_1;
        public byte Name_2;
        public byte Name_3;
        public byte Name_4;
        public byte Name_5;
        public byte Name_6;
        public byte Name_7;
        public int VirtualSize;
        public int VirtualAddress;
        public int SizeOfRawData;
        public int PointerToRawData;
        public int PointerToRelocations;
        public int PointerToLinenumbers;
        public short NumberOfRelocations;
        public short NumberOfLinenumbers;
        public int Characteristics;
    }

    static class ImageSectionReader
    {
        public static string NameString(this _IMAGE_SECTION_HEADER section)
        {
            var name = new[] { section.Name_0
                                   , section.Name_1
                                   , section.Name_2
                                   , section.Name_3
                                   , section.Name_4
                                   , section.Name_5
                                   , section.Name_6
                                   , section.Name_7
                };

            return section.Name_0 == Convert.ToByte('/') ?
                System.Text.Encoding.ASCII.GetString(name, 0, 8).TrimEnd('\0')
                : System.Text.Encoding.UTF8.GetString(name, 0, 8).TrimEnd('\0');
        }
    }

    struct _IMAGE_EXPORT_DIRECTORY
    {
        public int Characteristics;
        public int TimeDateStamp;
        public short MajorVersion;
        public short MinorVersion;
        public int Name;
        public int Base;
        public int NumberOfFunctions;
        public int NumberOfNames;
        public int AddressOfFunctions;     // RVA from base of image
        public int AddressOfNames;         // RVA from base of image
        public int AddressOfNameOrdinals;  // RVA from base of image
    }


}
