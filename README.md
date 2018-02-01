# DES-decrypter

Full description of this project is provided in "DES descryption.pdf"

Compile with: clang++ main.cpp crypt3.cpp --std=c++11 -fopenmp -o ompDES_cracker 

Help inline: ./ompDES_cracker --help

Example usage: ./ompDES_cracker 23101995 10 -d dictionary.txt -nt 8 -r

Authors: Niccolò Bellaccini nicco.b.93@gmail.com https://github.com/kinik93
         Tommaso Aldinucci tommaso.aldinucci@icloud.com https://github.com/tom1092
