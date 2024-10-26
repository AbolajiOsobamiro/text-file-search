This is a command line tool to search for any string or set of strings in a text file. It uses the memory mapping (mmap) method of file search, and therefore, is very fast, giving results in less than 0.5 milliseconds.

To use this tool, download the source code and replace the 200k.txt file with your desired text file, but make sure that that file is also named 200k.txt, as this file name in hardcoded into the code. Otherwise, you could go through the hassle of changing the name of the text file in the code, but I think that will be very stressful.

This source code is accompanied by a speed report, containing an analysis of the various other file search methods and algorithms that I tested before deciding on using the memory mapping method.

I hope you enjoy using this tool as much as I enjoyed deveoping it.
