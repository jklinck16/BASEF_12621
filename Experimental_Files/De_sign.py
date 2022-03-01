# https://www.geeksforgeeks.org/rsa-digital-signature-scheme-using-python/


M = input("Enter M (Message)")
S = int(input("Enter S"))
e = input("Enter e (public key)")
n = int(input("Enter n"))

num = ""
for i in M:
    if i.isdigit():
        num = num + i

de = ""
for i in e:
    if i.isdigit():
        de = de + i


M1 = (S**int(de)) % n


print(S)
print(de)
print(n)
print(num)
print(M1)

M1_text = ""
for i in str(M1):
    if i.isdigit():
        M1_text = M1_text + i

# If M = M1 only then Bob accepts
# the message sent by Alice.

if num == M1_text:
	print("As M = M1, Accept the\
	message sent by Alice")
else:
	print("As M not equal to M1,\
	Do not accept the message\
	sent by Alice ")
