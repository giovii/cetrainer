# cetrainer
A trainer for the cheat engine tutorial in golang (x64) [WIP]

* Step2 is solved with a simple write of 1000 to the right address
* Step3 is solved in the same way but we have to read many poiters before we get the right value and we have to set the value to 5000
* step4 is solving finding the address of a float and a double and put them to 5000
* Step5 is solved with the nopping of the instrution that change the value
* Step6 may require to be runned a couple of time in order to get solved, we force the write of the value 5000 to an address with a for loop
* Step7 is solved changing the sub with an add of 2
* Step8 may require to be runned a couple of time in order to get solved, we force the write of the value 5000 to an address with a for loop
* Step9 is  bit more complex (and fun) compared to the others first we check in the whole program for an array of byte that is unique in the program, once we found it we do a code cave to manipulate the behaviour of the program, first we allocate some memory in a free address, then we wrte the jump to that address instea of the sub instruction and we write our code to the new allocated memory, finally we make it executable

graphic level are still to be finished

