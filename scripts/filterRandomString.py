from stringlifier.api import Stringlifier
import time
import sys

# GROUP_SIZE = 10000 # Maximam size for 16G memory

def checkAndSave(strings, outputFile):
    stringlifier = Stringlifier()
    with open(outputFile, 'a+') as out_fd:
        res = stringlifier(strings)
        for i, string in enumerate(res):
            if '<RANDOM_STRING>' in string:
                continue
            else:
                out_fd.write(strings[i])

def filter(inputFile, outputFile, groupSize):
    print(inputFile, outputFile, groupSize)
    start = time.time()
    strings = []
    with open(inputFile, 'r') as fd:
        for i, line in enumerate(fd):
            if i > 0 and i % groupSize == 0:
                checkAndSave(strings, outputFile)
                print("[+] Stringlify {} lines, time: {}.".format(i, time.time()-start))
                strings = []
                start = time.time()
            else:
                strings.append(line)
    
    if strings:
        checkAndSave(strings, outputFile)
        print("[+] Stringlify {} lines, time: {}.".format(i, time.time()-start))


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python {} <input> <output> <groupsize>".format(sys.argv[0]))
    else:
        input = sys.argv[1]
        output = sys.argv[2]
        groupSize = int(sys.argv[3])
        filter(input, output, groupSize)
