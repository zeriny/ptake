import os
import sys

def splitFile(sldFile, outputBase, l):
    with open(sldFile, 'r') as fd:
        for i, line in enumerate(fd):
            if i < 10000:
                continue
            if i == 100000:
                break
            outputPath = os.path.join(outputBase, "alexa_{}0k".format(int(i/l) + 1))
            if not os.path.exists(outputPath):
                os.mkdir(outputPath)
            outputFile = os.path.join(outputPath, "sld.txt")
            with open(outputFile, 'a+') as out_fd:
                out_fd.write(line)
    print("Split {} to {}".format(sldFile, outputBase))


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python {} <sldFile> <outputBase> <lines>".format(sys.argv[0]))
    else:
        input = sys.argv[1]
        output = sys.argv[2]
        lines = int(sys.argv[3])
        splitFile(input, output, lines)