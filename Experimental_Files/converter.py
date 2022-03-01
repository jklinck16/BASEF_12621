import hashlib
import PyPDF2


def read(directory):
    file = open(directory, 'rb')
    fileReader = PyPDF2.PdfFileReader(file)
    print(fileReader.numPages)

    pageObj = fileReader.getPage(0)
    print(pageObj.extractText())

    #fileText = fileReader.getFormTextFields()
    #print(fileText)

def convert(str):
    encoded=str.encode()
    result = hashlib.sha256(encoded)
    print("String : ")
    print(str)
    print("Hash Value : ")
    print(result)
    print("Hexadecimal equivalent: ",result.hexdigest())
    print("Digest Size : ")
    print(result.digest_size)
    print("Block Size : ")
    print(result.block_size)



read('/Users/jeffreyklinck/Desktop/Blockchain/Test_Files/Test_2.pdf')
#convert('test')
