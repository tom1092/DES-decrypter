/*-***********************
* Compiler errors
*************************/
#ifndef _OPENMP
#   error "OPENMP framework is required"
#endif


/*-***********************
*   Dependencies
*************************/
#include <omp.h>
#include <chrono>
#include <math.h>
#include <fstream>
#include <algorithm>
#include "ArgsParser.h"
#include "crypt3.h"

/*-***********************
*   Constants
*************************/

#define BYTE_PSW_CRYPTED 16
#define SALT_LENGTH 2
#define N_SYMBOLS 10 //The number of accepted symbols for the bruteforce ([0...9])


/*-***********************
*   Functions declarations
*************************/


double dictionary_attack(char* psw, char * salt, const std::string& dict_path, const int& n_threads, const bool& random);
double bruteForce_attack(char *psw, char *salt, const int& n_threads);
inline int myrandom (int i) { return std::rand()%i;}
void getStringDictionary(std::vector<std::string>& dictionary, const std::string& dict_path, const bool& random);
void generateCombination(int v[], int k, int i);




/**
 * Given an index i generate a k-characters combination and save it in v[] array
 */
void generateCombination(int v[], int k, int i){
    for (int j=0; j<(k-1);j++){
        v[j] = i / (int)(pow((double) N_SYMBOLS ,(double)((k-1)-j)));
        i = i % (int)(pow((double) N_SYMBOLS ,(double)((k-1)-j)));
    }
    v[k-1] = i % N_SYMBOLS;
}



/**
 * Get the dictionary located in dict_path randomizing final items if required
 * @param dictionary data structure that will store the resulting dictionary
 * @param dict_path path where is currently stored the dictionary file
 * @param random indicates if the resulting dictionary will be randomized
 */
void getStringDictionary(std::vector<std::string>& dictionary, const std::string& dict_path, const bool& random){
    std::ifstream dict;
    dict.open(dict_path);
    std::string line;
    if(dict.is_open()){

        while ( getline (dict,line) )
        {
            dictionary.push_back(line);
        }
        dict.close();
    }
    if (random) {
        srand(time(NULL));
        std::random_shuffle(dictionary.begin(), dictionary.end(), myrandom);
    }
}


/**
 * Performs a dictionary attack to find the password passed by argument
 * @param psw the password
 * @param salt the salt
 * @param dict_path path where is currently stored the dictionary file
 * @param n_threads the number of threads executing the key-search loop
 * @param random a bool variable indicates if randomize the dictionary loaded
 * @return the time passed to find the password
 */
double dictionary_attack(char* psw, char * salt, const std::string& dict_path, const int& n_threads, const bool& random){

    std::vector<std::string> dictionary;
    getStringDictionary(dictionary, dict_path, random);
    char crypted[BYTE_PSW_CRYPTED];
    crypt(psw,salt,crypted);

    printf("Password crypted: %s", crypted);
    printf("\n\nSearching...\n\n");

    std::chrono::duration<double> timePassed;
    auto start = std::chrono::high_resolution_clock::now();

#   pragma omp parallel num_threads(n_threads)
    {
        char* comb = (char*)malloc(8);
        char guess[BYTE_PSW_CRYPTED];

#       pragma omp for schedule(static)
        for(int i = 0;i<dictionary.size(); i++) {
            strcpy(comb, dictionary.at(i).c_str());
            //printf("\n%s",comb); //uncomment this line to view all combination tested

            crypt(comb, salt,guess);

            if (strcmp(guess,crypted)==0) {
                auto end = std::chrono::high_resolution_clock::now();
                timePassed = end - start;
                printf("\nPassword found: %s", comb);
                printf("\nComputation time: %f s",timePassed.count());
            }
        }

        free(comb);
    }
    return timePassed.count();
}



/**
 *  Performs a brute force attack to find the password passed by argument
 * @param psw the password
 * @param salt the salt
 * @param n_threads the number of threads executing the key-search loop
 * @return the time passed to find the password
 */
double bruteForce_attack(char *psw, char *salt, const int& n_threads) {

    int k = strlen(psw) + strlen(salt);
    char symbols[] = "0123456789";
    int n = strlen(symbols);
    char crypted[BYTE_PSW_CRYPTED];
    long size = (long)pow((double)n,(double)k);
    crypt(psw,salt,crypted);

    printf("Password crypted: %s", crypted);
    printf("\n\nSearching...\n");

    std::chrono::duration<double> timePassed;
    auto start = std::chrono::steady_clock::now();

#   pragma omp parallel num_threads(n_threads)
    {
        int test[k];
        char* comb = (char*)malloc(k);
        char* attack_psw = (char*)malloc(strlen(psw));
        char attack_salt[SALT_LENGTH];
        char guess[BYTE_PSW_CRYPTED];

#       pragma omp for schedule(static)
        for(int i=0; i<size; i++){

            generateCombination(test, k, i);

            //Convert test to char array
            for (int j =0; j<k; j++){
                sprintf(&(comb[j]), "%d", test[j]);
            }

            strncpy(attack_psw,comb,strlen(psw)); //copy only the password
            attack_salt[0] = comb[strlen(comb)-strlen(salt)]; //take first salt digit
            attack_salt[1] = comb[strlen(comb)-strlen(salt)+1]; //take second salt digit

            //uncomment under line to view all combination tested
            //printf("\nThread %d test the string %s", omp_get_thread_num(), comb);

            crypt(attack_psw, attack_salt,guess);

            if (strcmp(guess,crypted)==0) {
                auto end = std::chrono::steady_clock::now();
                timePassed = end - start;
                printf("\nPassword found: %s", attack_psw);
                printf("\nComputation time: %f s",timePassed.count());
            }
        }
        free(comb);
        free(attack_psw);
    }
    return timePassed.count();
}



int main(int argc, char* argv[]) {

    CLParser parser(argc,argv, true);
    char psw[strlen(parser.get_arg(1).c_str())];
    char salt[2];
    int n_threads = omp_get_num_procs();
    std::string path;
    double time_passed;

    if (argc < 3 || parser.get_arg(1)=="--help" || argc> 8){

        printf("\nUSAGE:   ");
        printf("ompDES_cracker    <8 characters password> <2 characters salt> [Options]\n\n");
        printf("OPTIONS:\n");
        printf("-d    <dictionary_path>:   Enable dictionary attack (default: brute force attack)\n");
        printf("-nt   <num_threads>:       Set the number of threads (default: number of logical cores)\n");
        printf("-r                         Randomize attempts (only for dictionary) \n\n");
        return 0;

    }

    strcpy(psw,parser.get_arg(1).c_str());
    strcpy(salt,parser.get_arg(2).c_str());

    if (parser.get_arg("-nt")!=""){
        n_threads = atoi(parser.get_arg("-nt").c_str());
    }
    if (parser.get_arg("-d")!=""){
        path = parser.get_arg("-d");
        printf("\n-----SELECTED MODE: DICTIONARY-----\n\n");
        time_passed = dictionary_attack(psw,salt,path,n_threads,parser.find_arg("-r"));

    }
    else {
        printf("\n-----SELECTED MODE: BRUTEFORCE-----\n\n");
        time_passed = bruteForce_attack(psw,salt,n_threads);
    }


    return 0;
}