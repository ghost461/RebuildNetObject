/*
 * Program example of Linked List
 */
//Implementation file
//ElementType:Define the type when used.

#include<stdlib.h>
#include<stdio.h>
#include<arpa/inet.h>
#include"List.h"

//IP_MAC_QQ NodeList
struct Information
{
	//IPµØÖ·
	struct in_addr ip_address;
	//MACµØÖ·
	u_int8_t ether_host[6];
	//QQºÅ
	int qq_number;
};

struct Node
{
	ElementType Element;
	Position Next;
};

//Make a empty Element(struct Information)
ElementType MakeEmptyElement()
{
	ElementType X;
	X = (ElementType)malloc(sizeof(struct Information));
	if(X == NULL)
	{
		printf("Out of space!!!");
		return NULL;
	}
	X->qq_number = 0;
	return X;
}

//Return true if two Element are equal
int IsEqual(ElementType X, ElementType Y)
{
	if(X->qq_number == Y->qq_number)
		return 1;
	return 0;
}

//Set qq_number of Element X
void SetQQnumber(int qq, ElementType X)
{
	X->qq_number = qq;
}

//Read qq_number of Element X
int ReadQQnumber(ElementType X)
{
	return X->qq_number;
}

//Set ip_address of Element X
void SetIPaddress(struct in_addr ip_address, ElementType X)
{
	X->ip_address = ip_address;
}

//Read ip_address of Element X
struct in_addr ReadIPaddress(ElementType X)
{
	return X->ip_address;
}

//Print the Element(ip_address and qq_number) of X
void printElement(ElementType X)
{
	printf("%s\t", inet_ntoa(ReadIPaddress(X)));
	printf("%d\n", ReadQQnumber(X));
}

//Make a empty list
List MakeEmptyList()
{
	PtrToNode L;
	L = (List)malloc(sizeof(struct Node));
	if(L == NULL)
	{
		printf("Out of space!!!");
		return NULL;
	}
	L->Next = NULL;
	L->Element = NULL;
	return L;
}

//Make a empty node
Position MakeEmptyNode()
{
	PtrToNode L;
	L = (List)malloc(sizeof(struct Node));
	if(L == NULL)
	{
		printf("Out of space!!!");
		return NULL;
	}
	L->Next = NULL;
	L->Element = MakeEmptyElement();
	return L;
}

//Return true if L is empty
int IsEmpty(List L)
{
	//"nullptr" in C++, if it not usable(In C), use "NULL" or '0'
	return L->Next == NULL;
}

//Return true if P is the last position in list L
int IsLast(Position P, List L)
{
	return P->Next == NULL;
}

//Return Position of X in L; NULL if not found
Position Find(ElementType X, List L)
{
	Position P;
	P = L->Next;
//	while(P != NULL && P->Element != X)
	while(P != NULL && !IsEqual(P->Element, X))
		P = P->Next;
	return P;
}

//Delete first occurrence of X from a list
//If you changed FindPrevious(), you may have to change this function
void Delete(ElementType X, List L)
{
	Position P, TmpCell;
	P = FindPrevious(X, L);
	//Assumption of header use
	if (!IsLast(P, L))
	{
		TmpCell = P->Next;
		//Bypass deleted cell
		P->Next = TmpCell->Next;
		//!!!!!!
		free(TmpCell);
	}
}

//If X is not found, then Next field of returned
//Position is NULL
Position FindPrevious(ElementType X, List L)
{
	Position P;
	P = L;
//	while(P->Next != NULL && P->Next->Element != X)
	while(P->Next != NULL && !IsEqual(P->Next->Element, X))
		P = P->Next;
	return P;
}

//Insert (after legal position P)
//Parsmeter L is unused in this implementation
void Insert(ElementType X, List L, Position P)
{
	Position TmpCell;
	//malloc() return void*, need to convert the data type(now it is Position).
	TmpCell = (Position)malloc(sizeof(struct Node));
	if(TmpCell == NULL)
		printf("Out of space!!!");
	TmpCell->Element = X;
	TmpCell->Next = P->Next;
	P->Next = TmpCell;
}

//Delete list L
void DeleteList(List L)
{
	Position P, Tmp;
	P = L->Next;
	L->Next = NULL;
	while(P != NULL)
	{
		Tmp = P->Next;
		free(P);
		P = Tmp;
	}
}

//Return the position of last node in L
Position Last(List L)
{
	Position P;
	P = L;
	while(P->Next != NULL)
		P = P->Next;
	return P;
}
