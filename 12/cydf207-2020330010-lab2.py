#from curses.ascii import islower
import random
from string import ascii_lowercase

WORDLIST_FILENAME = "/Users/dd/Documents/CYDF/12/week2/words.txt"

def load_words():
    """
    returns: list, a list of valid words. Words are strings of lowercase letters.

    Depending on the size of the word list, this function may
    take a while to finish.
    """
    print("Loading word list from file...")
    # inFile: file
    inFile = open(WORDLIST_FILENAME, 'r')
    # line: string
    line = inFile.readline()
    # wordlist: list of strings
    wordlist = line.split()
    print("  ", len(wordlist), "words loaded.")
    return wordlist

def choose_word(wordlist):
    """
    wordlist (list): list of words (strings)

    returns: a word from wordlist at random
    """
    return random.choice(wordlist)

all_words_list = load_words()
secret_word = choose_word(all_words_list)
print(secret_word)
#-------------------------------------
# Your code can start from here
#-------------------------------------
chances=10 #chances안에 단어를 맟추어야 함
len=len(secret_word)#secret_word의 길이를 저장
myWord=['_']*len#맞춘 알파벳을 저장
print("Welcome to Hangman !")
print("Let’s guess a", len, "letter word.")
print("--------------------")
alphabet_list=list(ascii_lowercase)

i=chances
while i>0 and '_' in myWord:#단어를 모두 찾지 않았고 기회가 남았다면~
    print("You currently have", i, "guesses left.")
    print("Available letters: ",*alphabet_list,sep='')
    letter=input("Please guess a letter: ")#입력받은 문자 저장
    if letter in alphabet_list:#아직 사용하지 않은 알파벳이 입력되었다면!
        if letter in secret_word:#입력받은 문자가 secret_word에 포함되어 있다면 myword의 '_'을 해당 문자로 치환
            for j in range(len):
                if secret_word[j]==letter:
                    myWord[j]=letter
            print("Good guess:", *myWord)
        else:
            if i==1:
                print("Ooops! Not enough guess left for :", *myWord)
            else:
                print("Sorry. That letter is not in my word :",*myWord)
        i-=1
        alphabet_list.remove(letter)#한번 사용한 알파벳 삭제
    elif letter=='?':
        for j in range(len):
            if myWord[j]=='_':#처음 나타난 빈칸과 같은 알파벳을 채움
                for k in range(j,len):
                    if secret_word[j]==secret_word[k]:
                        myWord[k]=secret_word[j]
                break            
        print("Letter", myWord[j], "is revealed :", *myWord)
        i-=3
    else:
        print("Nope. That is not a valid letter :", *myWord)

    print("--------------------")

#Winning
if '_' not in myWord:
    score=4*i+3*len
    print("Good Job! You won with score of", score, ".")
#Losing
else:
    print("The secret word is ‘",secret_word,"'.",sep='')
    

    
    



