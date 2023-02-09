# OS-Lab4
Building a FAT32 file recovery tool called Need You to Undelete my FILE, or nyufile for short.

In this lab, I:
- Learned the internals of the FAT32 file system.
- Learned how to access and recover files from a raw disk.
- Got a better understanding of key file system concepts.
- Became a better C programmer, and learned how to write code that manipulates data at the byte level and understand the alignment issue.

In this lab, I wrote code that validated usage, printed the file system information, listed the root directory, recovered a small file, recovered a large contiguously-allocated file, detected ambiguous file recovery requests, recovered a contiguously-allocated file with SHA-1 hash and recovered a non-contiguously allocated file.
