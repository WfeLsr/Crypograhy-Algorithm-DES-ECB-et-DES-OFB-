

/* This application enables you to encrypt and decode a block using the ECB cryptographic mode DES method.*/
/* First, enter the key after dividing the message into blocks of 8; if the block numbers (bn) are less than 8, padding is added;
 if they are greater than 8, the reverse is true(for decryption). English comments between braket*/


//French
/* Ce programme permet de chiffrer et déchiffrer un bloc en utilisant l'algorithme du DES mode cryptographique ECB*/
/* Tous d'abords la saisit de clé aprés découpage du message en blocs de 8 si < ou > on fait remplie ce qu'il faut
 par des zéros (padding) et de meme pour le dechiffrement.*/
/* ------------------------------------------------------------------------------------------------------- */



#include   <dos.h>
#include <CONIO.H>
#include <stdlib.h>
#include <stdio.h>
#include <sys\stat.h>
#include	 <PROCESS.H>
#define Max 1000

int size(char* name){
FILE *fp;
int size;
fp=fopen(name,"rb");
if (fp){
  fseek(fp,0,2);
  size=ftell(fp)/sizeof(int);
 fclose(fp);
}
return size;
}
void enregistrer_int(int *tab,int t,char *non)
{FILE *fp;
fp=fopen(non,"w");
if (fp==NULL) puts("The file can not be found");
fwrite(tab,sizeof(int),t,fp);
fclose(fp);
}
int *lecture(char* name,int t)
{int *tab=(int*)malloc(t*sizeof(int));
FILE *fp;
fp=fopen(name,"r");
fread(tab,sizeof*tab,t,fp);
fclose(fp);
return tab;
}
//fonction DES en mode ECB ==> chiffrer (e=0 et f=1)//dechiffre (e=1 et f=-1)
int* DES(int e,int f,int* b,int cl[17][49])
{int bi[65]={7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0};
int perm[65]={58,50,42,34,26,18,10,2,
	  60,52,44,36,28,20,12,4,
	  62,54,46,38,30,22,14,6,
	  64,56,48,40,32,24,16,8,
	  57,49,41,33,25,17, 9,1,
	  59,51,43,35,27,19,11,3,
	  61,53,45,37,29,21,13,5,
	  63,55,47,39,31,23,15,7};
int bj[33]={3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0};
int invperm[65]={40,8,48,16,56,24,64,32,
		 39,7,47,15,55,23,63,31,
		 38,6,46,14,54,22,62,30,
		 37,5,45,13,53,21,61,29,
		 36,4,44,12,52,20,60,28,
		 35,3,43,11,51,19,59,27,
		 34,2,42,10,50,18,58,26,
		 33,1,41, 9,49,17,57,25};
int select[49]={32, 1, 2, 3, 4, 5,
		 4, 5, 6, 7, 8, 9,
		 8, 9,10,11,12,13,
		12,13,14,15,16,17,
		16,17,18,19,20,21,
		20,21,22,23,24,25,
		24,25,26,27,28,29,
		28,29,30,31,32,1};
int table[8][4][16]={{{4,14,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};
int bloc[8][6]={{ 1, 2, 3, 4, 5, 6},
		{ 7, 8, 9,10,11,12},
		{13,14,15,16,17,18},
		{19,20,21,22,23,24},
		{25,26,27,28,29,30},
		{31,32,33,34,35,36},
		{37,38,39,40,41,42},
		{43,44,45,46,47,48}};
int perm3[33]={16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
		 2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
     int *resultat=(int*)malloc(sizeof(int)*8);
	 int i,z,j,iter,lig,col,p;
	 int res[8],g[33],temp[33],d[33],s[49],bk[65],bkl[65];
/* conversion du bloc en bits (convert blocs to bits) */
			 for(i=1 ;i<=64;i++)
			 {
				p=bi[i-1];
				bkl[i]=(b[(i-1)/8] & (1<<p)) >>p;
			 }
/* permutation initiale (Initial swap)*/
			for(i=1;i<=64;i++)
				bk[i]=bkl[perm[i-1]];
/* 16 itérations (16 iterations)*/
			for(iter=1;iter<=16;iter++)
			{
/* séparation des blocs G et D (separation of blocks G and D) */
				for(i=1;i<=32;i++)
				{
				 g[i]=bk[i];
				 d[i]=bk[i+32];
				}
/* selection de bits avec répétitions (bit selection with repetitions)*/
				for(i=1;i<=48;i++)
				 s[i]=d[select[i-1]];
/* ou exclusif avec le bloc: Phase importante (or exclusive with the block: Important phase)*/
				z=e* 17+f*iter;   // e=0 et f=1 on aura le chiffrement (la clé K de K1 à K16 pour e=1 et f=-1 on aura le déchiffrement (la clé K de k16 à k1)
				for(i=1;i<=48;i++) //  (e=0 and f=1 encryption (the key K from K1 to K16 for e=1 and f=-1 decryption (the key K from k16 to k1))
					s[i]=s[i]^cl[z][i];
/* table de selection (selection table)*/
				for(j=0;j<=7;j++)
				{
					lig=2*s[bloc[j][0]]+s[bloc[j][5]];
					col=8*s[bloc[j][1]]+4*s[bloc[j][2]]+2*s[bloc[j][3]]+ s[bloc[j][4]];
					res[j]=table[j][lig][col];
				}
				for(i=1;i<=32;i++)
				{
					p=bj[i];
					s[i]=(res[(i-1)/4] & (1<<p)) >>p;
				}
/* permutation P3 et fin de l'itération (P3 permutation and end of iteration)*/
				if (iter != 16)
					for(i=1;i<=32;i++)
					{
						 temp[i]=s[perm3[i-1]]^g[i];
						 g[i]=d[i];d[i]=temp[i];
					 }
				else
					for(i=1;i<=32;i++)
					{
						temp[i]=s[perm3[i-1]]^g[i];
						g[i]=temp[i];
					}
				for(i=1;i<=32;i++)
				{
					 bk[i]=g[i];
					 bk[i+32]=d[i];
				}
				if (iter == 16)
				{
					 for(i=1;i<=64;i++)
						bkl[i]=bk[invperm[i-1]];
					 for(i=1;i<=64;i++)
						 bk[i]=bkl[i];
				 }
			}
         for(i=0;i<=7;i++)
			{ p=0;
				 for(j=1;j<=8;j++)
						p+=(1<<(8-j))*bk[8*i+j];
				resultat[i]=p;
			}
return resultat;
}

int main (void)
{
/* données numériques du DES (digital data from DES) */

int bi[65]={7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0};
int perm2[49]={14,17,11,24, 1, 5,
		3,28,15, 6,21,10,
		 23,19,12, 4,26, 8,
		 16, 7,27,20,13, 2,
		 41,52,31,37,47,55,
		 30,40,51,45,33,48,
		  44,49,39,56,34,53,
		  46,42,50,36,29,32 };
int s_cle[57]={57,49,41,33,25,17, 9,
		1,58,50,42,34,26,18,
		 10, 2,59,51,43,35,27,
		 19,11, 3,60,52, 4,36,
		 63,55,47,39,31,23,15,
		7,62,54,46,38,30,22,
		 14, 6,61,53,45,37,29,
		 21,13, 5,28,20,12,4 };
int decal[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
     int *claire=(int*)malloc(sizeof(int)*Max);
	 int *decrym=(int*)malloc(sizeof(int)*Max);
     int *encrym_fich=(int*)malloc(sizeof(int)*Max);
     int *encrym=(int*)malloc(sizeof(int)*Max);
     int *inter=(int*)malloc(sizeof(int)*8);
     int * b = (int*)malloc(sizeof(int)*8);
	 unsigned char cle[8];
     int l[29],r[29],bk[65],clek[57],cl[17][49];
	 int i,taille,k,m=0,q,stop=0,iter,j,p,choix;

	 printf("\n\n");
     printf ("\n\t\t\t* ENCRYPTION/DECRYPTION : * ");
	 printf("\n\n");
     printf ("\t\t\t  * STANDARD DATA ENCRYPTION : * ");
     printf("\n\n");
	 printf ("\t\t * DES-ECB, regardless of the message's size: * ");

     printf("\n\n Please type the security key (eight characters): \n");

for (i=0;i<8;i++)
{cle[i]=getch();
putchar('*');
}
/* Conversion en bits de la clé K (Bit conversion of key K) */
	 for(i= 1 ;i<=64;i++)
	 { p=bi[i-1];
		 bk[i]=(cle[(i-1)/8] & (1<<p)) >>p;
	 }
	 for(i=1;i<=56;i++)
		clek[i]=bk[s_cle[i-1]];
/* calcul des 16 sous clés de 48 bits (calculation of the 16 48-bit subkeys)*/
	 for(iter=1;iter<=16;iter++)
	 {
		for(i=1;i<=28-decal[iter-1];i++)
		 {
			l[i]=clek[i+decal[iter-1]];
			r[i]=clek[i+28+decal[iter-1]];
		 }
		for(i=28-decal[iter-1]+1;i<=28;i++)
		 {
			l[i]=clek[i-28+decal[iter-1]];
			r[i]=clek[i+decal[iter-1]];
		 }
		 for(i=1;i<=28;i++)
		 {
			clek[i]=l[i];
			clek[i+28]=r[i];
		 }
		 for(i=1;i<=48;i++)
		 cl[iter][i]=clek[perm2[i-1]];
     }

puts("\t Please make your selection from the following menu:\n ");
 do {
    system("cls");
      puts("\n\n\n\n");
      puts("\t\n\t\t************* Menu : *************");
      puts("\n\n");
      puts("\t\t\t 1:Encrypt.");
      puts("\n\n");
      puts("\t\t\t 2:Decipher.");
      puts("\n\n");
      puts("\t\t\t 3:Exit.");
      scanf("%d",&choix);
      getchar();
      system("cls");
switch(choix)
{   case 1:
         {   /*lecture du message à chiffrer (reading the message to be encrypted)*/
             printf("\n\n Please type the message to be encrypted : \n");
             printf("\n*Type backspace to delete");
             printf(" This will display l before deletion *:\n\n");
             while(stop<Max)
            {claire[stop]=getch();
             //pour effacer un caractere taper back-space (to delete a character type back-space)
             while(claire[stop]==8) stop=stop-2;
             //pour arreter la saisie au clavier tapper entrée (to stop keyboard input, type enter)
             if(claire[stop]==13)
             break;
             putchar(claire[stop]);
             //taille du message (message size)
             stop++;
            }
             printf("\n----- Saving the raw message in clear.txt file... :");
             enregistrer_int(claire,stop,"claire.txt");
             printf("\n----- Raw message contains %d character(s).:",stop);
             printf("\n----- Block cutting and encryption of 64bits=8bytes: ");
             //decoupage si message a une taille divisible par 8 ou une taille inferieur à 8.
			 //(cutting if message has a size divisible by 8 or a size less than 8.)
             k=0;
             do
            {printf("\n----->n:%d=>",k+1);
             for(m=0;m<8;m++)
              { if(stop%8==stop&&m>=stop) b[m]=0;taille=8;
                b[m]=claire[m+k*8];
              }
             b=DES(0,1,b,cl);
             puts("");
             for(m=0;m<8;m++){encrym[m+8*k]=b[m];
                              printf("%c",encrym[m+8*k]);
                             }
             k++;
            }while(k<stop/8);
             //decoupage si message taille>8 on crypte la partie qui reste
			 //(cutting if message size>8 we encrypt the remaining part)
             if(stop%8!=0&&stop%8!=stop)
            {taille=stop;
             printf("\n----->n:%d :=>",k+1);
             puts("");
             q=stop/8;
             j=0;
             for(m=8*q;m<(8*q)+8;m++)
            {if(m<stop) b[j]=claire[m];
             else {b[j]=0; taille++;}
             j++;
            }
             b=DES(0,1,b,cl);
             for(m=0;m<8;m++)
            {encrym[m+8*k]=b[m];
             printf("%c",encrym[m+8*k]);
            }
            }
             printf("\n----- Saving the encrypted message in encrypt.txt file... :");
             enregistrer_int(encrym,taille,"encrypt.txt");
             puts("\n----- Final encryption result :");
             for(m=0;m<taille;m++)
             printf("%c",encrym[m]);
             puts("\n\n");
             printf("\n\n\t Type enter to return to the menu.");
     getchar();
     system("cls");
     break ;
    }
    case 2:
    {        printf("\n----- Decryption of the file:");
             printf("\n----- Loading the encryption file... :");
             taille=size("encrypt.txt");
             encrym_fich=lecture("encrypt.txt",taille);
             puts("\n----- Reading the encrypted file: ");
             for(i=0;i<taille;i++) printf("%c",encrym_fich[i]);
             puts("\n----- Decryption of the message encrypted in blocks of 8 bytes: ");
             k=0;
             int a=taille/8;
             while(k<a)
            {for(m=0;m<8;m++) b[m]=encrym_fich[m+(k*8)];
             inter=DES(1,-1,b,cl);
             printf("\n )%d(=> ",k+1);
             for(int m=0;m<8;m++)
            {decrym[m+8*k]=inter[m];
             printf("\n \t %c ==>> %c ",encrym_fich[m+(8*k)],decrym[m+(8*k)]);
            }
             k++;
            }
             stop=size("claire.txt");
             puts("\n----- Final decrypted message: ");
             for(i=0;i<stop;i++) printf("%c",decrym[i]);
             enregistrer_int(decrym,stop,"decrym.txt");
             printf("\n\t Type enter to return to the menu.");
             puts(" \n \n ");
    getchar();
    system("cls");
    break ;
   }
}
}while(choix<3);
return (0);
}
