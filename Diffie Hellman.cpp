/*
Artur Henrique Brandão de Souza - 15/0118783

Brief:
Simulation of Diffie-Hellman algorithm that is  a method of securely exchanging cryptographic keys over a public channel

*/
#include <bits/stdc++.h>
#include <iostream>

#include <unistd.h> // sleep function
#include <cstdlib> // system clear
using namespace std;

uint64_t alice_sk, bob_sk, g, p, ga, gb, secret_key_alice, secret_key_bob;

void simulation(int menu){
    int enter;
    if(menu ==0){

        system("clear");    
        cout << "                             PASSO 1                            "<<endl;
        cout << " ---------------------------------------------------------------"<< endl;
        cout << "|__________Alice ________|_____Public_____|_________Bob_________|"<< endl;
        cout << "|                        |                |                     |"<< endl;
        cout << "|        alice_sk        |    g    p      |      bob_sk         |"<< endl;
        cout << "|                        |                |                     |"<< endl;
        cout << "|                        |                |                     |"<< endl;
        cout << "|                        |                |                     |"<< endl;
        cout << " ---------------------------------------------------------------"<< endl;
        cout << "\nValores atuais:" << endl;
        cout <<"\np = " << p << endl <<"g = " << g << endl;
        cout <<"alice_sk = " << alice_sk << endl <<"bob_sk = " << bob_sk << endl;
        cout << "\nAperte enter para continuar" << endl;
        
        while(1){
            if(cin.get()== '\n'){
                if(cin.get()== '\n'){
                    break;
                }
            }
        }

        system("clear");
        
    }
    else{
        if(menu == 1){
            cout << "                             PASSO 2                            "<<endl;   
            cout << " ---------------------------------------------------------------"<< endl;
            cout << "|__________Alice ________|_____Public_____|_________Bob_________|"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << "|        alice_sk        |    g    p      |      bob_sk         |"<< endl;
            cout << "|ga =   g^        mod p  |                |gb = g^      mod p   |"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << " ---------------------------------------------------------------"<< endl;
            cout << "\n Fazendo troca de chaves......\n"<< endl;
            sleep(3);

            cout << " ---------------------------------------------------------------"<< endl;
            cout << "|__________Alice ________|_____Public_____|_________Bob_________|"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << "|        alice_sk        |    g    p      |      bob_sk         |"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << "|                        |   gb    ga     |                     |"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << " ---------------------------------------------------------------"<< endl;
            
            cout << "\n Fazendo troca de chaves......\n"<< endl;
            

            sleep(3);  

            cout << " ---------------------------------------------------------------"<< endl;
            cout << "|__________Alice ________|_____Public_____|_________Bob_________|"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << "|        alice_sk        |    g    p      |      bob_sk         |"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << "|           gb           |                |        ga           |"<< endl;
            cout << "|                        |                |                     |"<< endl;
            cout << " ---------------------------------------------------------------"<< endl;
            cout << "\Valores atuais:\n" << endl;
            cout <<"p = " << p << endl <<"g = " << g << endl;
            cout <<"alice_sk = " << alice_sk << endl <<"bob_sk = " << bob_sk << endl;
            cout << "ga = " << ga << endl << "gb = " << gb << endl;
            cout << "\nAperte enter para continuar" << endl;
            
            while(1){
                if(cin.get()== '\n'){break;}
            }
            system("clear");    
        }
        else{
            if(menu == 2){
                 cout << "                             PASSO 3                            "<<endl;   
                cout << " ---------------------------------------------------------------"<< endl;
                cout << "|__________Alice ________|_____Public_____|_________Bob_________|"<< endl;
                cout << "|                        |                |                     |"<< endl;
                cout << "|        alice_sk        |    g    p      |       bob_sk        |"<< endl;
                cout << "|ka = gb^        mod p   |                |kb = ga^      mod p  |"<< endl;
                cout << "|                        |                |                     |"<< endl;
                cout << "|                        |                |                     |"<< endl;
                cout << " ---------------------------------------------------------------"<< endl;
    
                sleep(2); 

                cout << " ---------------------------------------------------------------"<< endl;
                cout << "|__________Alice ________|_____Public_____|_________Bob_________|"<< endl;
                cout << "|                        |                |                     |"<< endl;
                cout << "|        alice_sk        |    g    p      |      bob_sk         |"<< endl;
                cout << "|                        |                |                     |"<< endl;
                cout << "|           ka           |                |        kb           |"<< endl;
                cout << "|                        |                |                     |"<< endl;
                cout << " ---------------------------------------------------------------"<< endl;
                cout << "\n Valores atuais:\n" << endl;
                cout <<"p = " << p << endl <<"g = " << g << endl;
                cout <<"alice_sk = " << alice_sk << endl <<"bob_sk = " << bob_sk << endl;
                cout << "ka = " << secret_key_alice << endl << "kb = " << secret_key_bob << endl;
                cout << "\nAperte enter para encerrar a simulação" << endl;
                
                while(1){
                    if(cin.get()== '\n'){break;}
                }  


            }
        }    

    }


}

// calc a * b % p , evitando overflow - verificando a possibilidade de dividir o numerado e o denominador por dois usando shift
uint64_t mul_mod_p(uint64_t a, uint64_t b) { 
	uint64_t m = 0, aux;
	while(b) {
		if(b&1) {
			aux = p-a;
			if ( m >= aux) {
				m -= aux;
			} else {
				m += a;
			}
		}
		if (a >= p - a) {
			a = a * 2 - p;
		} else {
			a = a * 2;
		}
		b>>=1;
	}
	return m;
}

// calcula a^b % p
uint64_t pow_mod_p(uint64_t g, uint64_t person_key) {
	uint64_t aux;
    if (g > p) // caso o valor gerador for maior do que o valor primo passado; key_bob < p && key_alice < p && g < p 
		g%=p;
    if (person_key==1) {
		return g;
	}
	aux = pow_mod_p(g, person_key>>1);
	aux = mul_mod_p(aux,aux);
	if (person_key % 2) {
		aux = mul_mod_p(aux, g);
	}
	return aux;
}



void inserting_public_number(uint64_t &g, uint64_t &p){
    cout << "Escreva o valor do número gerador g:" << endl;
    cout << "Ou digite 0(zero) para um valor default " << endl;
    cin >> g ;
    if(g==0){
        g=5;
    }
    cout << "Escreva o valor de p (primo suficientemente grande)" << endl;
    cout << "Ou digite 0(zero) para o maior valor primo 64 bits" << endl;
    cin >> p;
    if(p==0){
        p  = 18446744073709551557; // Maior número primo de 64 bits
    }

}

// Como o valor max a ser retornado por um rand é entre 0 e  "RAND_MAX	2147483647", ou seja 7FFFFFFF, então utilizamos o shift para obter um valor  maior possível 
uint64_t random_number(){
    int aux_random = rand();
    uint64_t a,b,c,d;
    sleep(1);
    srand(time(NULL)); // Função random ser sempre aleatória pegando os segundos do computador para a função rand
    a = rand()%aux_random;
    b = rand()%aux_random;
    c = rand()%aux_random;
    d = rand()%aux_random;
    return a << 48 | b << 32 | c << 16 | d;
}

int main(){   
    int menu=0; 

    system("clear");
    // 1 passo - Inicializar valores das chaves privadas de Alice e Bob além de gerar os números de gerador e mod p(número primo grande) públicos 
    bob_sk = random_number();
    alice_sk = random_number();
    inserting_public_number(g, p);
    simulation(menu);
    // 2 passo - g^a_sk mod p
    ga = pow_mod_p(g, alice_sk);
	gb = pow_mod_p(g, bob_sk);
    menu++;
    simulation(menu);
    //3 passo - g^a *  mod p
    secret_key_alice = pow_mod_p(gb ,alice_sk);
	secret_key_bob = pow_mod_p(ga,bob_sk);
    menu++;
    simulation(menu);

    return 0;
}