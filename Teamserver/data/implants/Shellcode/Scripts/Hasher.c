#include <stdio.h>
#include <ctype.h>

long Hash( char* String )
{
  unsigned long Hash = 5381;
	int c;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

void ToUpperString(char * temp) {
  // Convert to upper case
  char *s = temp;
  while (*s) {
    *s = toupper((unsigned char) *s);
    s++;
  }
}

int main(int argc, char** argv) 
{
  if (argc < 2)
    return 0;

  ToUpperString(argv[1]);
  printf("\n[+] Hashed %s ==> 0x%x\n\n", argv[1], Hash( argv[1] )); 
  return 0;
}
