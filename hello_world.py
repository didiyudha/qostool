def hello(y):
    x = 2 + y
    print x
    return "hasil: ", x

if __name__ == '__main__':
    str_hasil, x = hello(2)
    print str_hasil + str(x)
