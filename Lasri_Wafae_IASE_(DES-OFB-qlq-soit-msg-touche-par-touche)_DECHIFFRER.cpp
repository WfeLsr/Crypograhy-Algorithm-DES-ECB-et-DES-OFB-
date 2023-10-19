
/* Ce programme permet de DECHIFFRER un bloc en utilisant l'algorithme du DES mode cryptographique OFB*/

/* This program allows you to DECIPHER a block using the OFB cryptographic mode DES algorithm*/
#include   <dos.h>
#include   <time.h>
#include   <stdlib.h>
#include <CONIO.H>
#include <stdio.h>
#include <string.h>
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
if (fp==NULL) puts("The file can ot be found");
fwrite(tab,sizeof(int),t,fp);
fclose(fp);
}

int *lecture(char* name,int t)
{int i,n;
int *tab=(int*)malloc(Max*sizeof(int));
FILE *fp;
fp=fopen(name,"r");
fread(tab,sizeof*tab,t,fp);
fclose(fp);
return tab;
}

char *lecture_char(char* name,int t)
{int i;
 char *tab;
tab=(char*)malloc(Max*sizeof*tab);
FILE *fp;
fp=fopen(name,"r");
fread(tab,sizeof*tab,t,fp);
fclose(fp);
return tab;
}

int main (void)
{
/* données numériques du DES */
int bi[65]={7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0,
	 7,6,5,4,3,2,1,0};
int bj[33]={3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0,
	 3,2,1,0};
int perm[65]={58,50,42,34,26,18,10,2,
	  60,52,44,36,28,20,12,4,
	  62,54,46,38,30,22,14,6,
	  64,56,48,40,32,24,16,8,
	  57,49,41,33,25,17, 9,1,
	  59,51,43,35,27,19,11,3,
	  61,53,45,37,29,21,13,5,
	  63,55,47,39,31,23,15,7};
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

int s_cle[57]={57,49,41,33,25,17, 9,
		1,58,50,42,34,26,18,
		 10, 2,59,51,43,35,27,
		 19,11, 3,60,52, 4,36,
		 63,55,47,39,31,23,15,
		7,62,54,46,38,30,22,
		 14, 6,61,53,45,37,29,
		 21,13, 5,28,20,12,4 };

int perm2[49]={14,17,11,24, 1, 5,
		3,28,15, 6,21,10,
		 23,19,12, 4,26, 8,
		 16, 7,27,20,13, 2,
		 41,52,31,37,47,55,
		 30,40,51,45,33,48,
		  44,49,39,56,34,53,
		  46,42,50,36,29,32 };

int table[8][4][16]={{{4,14,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
											{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};
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
int decal[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};


	 unsigned char cle[8],m;
	 int res[8],g[33],temp[33],d[33],s[49],l[29],r[29];
	 int bk[65],bkl[65],clek[57],cl[17][49];
	 int *b=(int*)malloc(sizeof(int)*8);
	 int c,iter,lig,col,a,e=0,f=1,j,p,w,des,i,z,stop;
	 char *claire=(char*)malloc(sizeof(char)*Max);
     int *stock_alea=(int*)malloc(sizeof(int)*Max);
	 int *encrym=(int*)malloc(sizeof(int)*Max);
	 int *decrym=(int*)malloc(sizeof(int)*Max);
     int *encrym_fich=(int*)malloc(sizeof(int)*Max);

	 printf("\n\n");
     printf ("\n\t\t\t\t* Decryption : * ");
     puts("\n");
     printf ("\t\t\t * DATA ENCRYPTION STANDARD : * ");
     printf("\n\n");
	 printf ("\t * DES-OFB reads each character individually regardless of the message's size *");
	 printf("\n\n");

     printf("\n\n DES-OFB reads each character individually regardless of the message's size \n");

for (i=0;i<8;i++)
{cle[i]=getch();
putchar('*');
}
b=lecture("alea.txt",8);
/* Conversion en bits de la clé K */
	 for(i=1;i<=64;i++)
	 { p=bi[i-1];
		 bk[i]=(cle[(i-1)/8] & (1<<p)) >>p;
	 }
	 for(i=1;i<=56;i++)
		clek[i]=bk[s_cle[i-1]];
/* calcul des 16 sous njqklhjk  clés de 48 bits */
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
stop=size("encrypt.txt");
 int k=0;
 do{
/* conversion du bloc en bits*/
        	 for(i=1 ;i<=64;i++)
			 {
				p=bi[i-1];
				bkl[i]=(b[(i-1)/8] & (1<<p)) >>p;
			 }

/* permutation initiale */
			for(i=1;i<=64;i++)
				bk[i]=bkl[perm[i-1]];
/* 16 itérations */
			for(iter=1;iter<=16;iter++)
			{
/* séparation des blocs G et D */
				for(i=1;i<=32;i++)
				{
				 g[i]=bk[i];
				 d[i]=bk[i+32];
				}
/* selection de bits avec répétitions */
				for(i=1;i<=48;i++)
				 s[i]=d[select[i-1]];
/* ou exclusif avec le bloc: Phase importante */
				z=e* 17+f*iter;   // e=0 et f=1 on aura le chiffrement (la clé K de K1 à K16 pour e=1 et f=-1 on aura le déchiffrement (la clé K de k16 à k1)
				for(i=1;i<=48;i++)
					s[i]=s[i]^cl[z][i];
/* table de selection */
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
/* permutation P3 et fin de l'itération */
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

/* ecriture du bloc chiffré */
			for(i=0;i<=7;i++)
			{
				 p=0;
				 for(j=1;j<=8;j++)
						p+=(1<<(8-j))*bk[8*i+j];
			     if(i==0) des=p;
            }
for (i=0;i<7;i++)  b[i]=b[i+1];
 b[7]=des;
//stockage des bit des octets fort
 stock_alea[k]=des;
 k++;}while(k<stop);

     encrym_fich=lecture("encrypt.txt",stop);
     puts(" \t\n...... After decryption : .......");
     for(i=0;i<stop;i++)
    {decrym[i]=encrym_fich[i]^stock_alea[i];
     printf("%c",decrym[i]);
    }
     puts(" \t\n...... Saving in decrypt.txt file ......");
     enregistrer_int(decrym,stop,"decrypt.txt");
     puts(" \t\n...... The message is .......");
     claire=lecture_char("claire.txt",stop);
     i=0;
     do
    {printf("%c",claire[i]);
     i++;
    }while(i<stop);
return(0);
}
