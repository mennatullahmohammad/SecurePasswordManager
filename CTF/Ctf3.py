def solve(filepath):
    with open(filepath, 'r') as f:
        numbers=list(map(int, f.read().split()))
    c=0
    ascii=[]
    for i in numbers:
        if i>126:
            ascii.append(i)
        if i % 2 == 0:
            c+=1
    even = c == len(numbers)
    decoded= []
    for n in numbers:
        original = n >> 1
        char= chr(original)
        decoded.append(char)
    flag = ''.join(decoded)
    print(F"FLAG: {flag}")
    return flag


if __name__ == "__main__":
    import sys
    filepath = sys.argv[1] if len(sys.argv) > 1 else "shifted.txt"
    solve(filepath)