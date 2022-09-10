while 1:
    n=input('Enter the number or type ’quit’ : ')
    try:
        if n.lower()=='quit':#string을 소문자로 바꾸는 함수 string.lower()
            print("Good Bye~")
            break
        
        if n.isnumeric():#string이 양의 정수일 때만 True반환
            n=int(n)
            primes=[False,False]+[True]*(n-1)#0은 시작 index를 맞추기 위해 False로 추가, 1은 소수가 아니므로 False, 일단 가장 작은 소수인 2부터 n까지 True로 설정
            caches=[2]#소수를 찾으면 저장함 separation을 구하는 데 이용됨, 가장 작은 소수 2의 separation을 구하기 위해 첫번째 원소는 2로 저장
            maxSep=0#max separation을 저장
            #에라토스테네스의 체를 이용한 소수 구하기
            for i in range(2,n+1):
                if primes[i]:#i가 소수라면 i보다 큰 i의 배수는 소수가 아니게 된다.
                    for j in range(i+i,n+1,i):
                        primes[j]=False
                    caches.append(i)#i는 소수이므로 추가
                    maxSep=max(maxSep,caches[-1]-caches[-2])
            #print(caches)
            num=len(caches)-1
            print("There are",num,"prime numbers less than or equal to",n,"and" ,maxSep, "is the maximum separation")
        else:
           print("Invalid input - Input should be a positive integer.") 
        
    except:
        print("error occured")
        
