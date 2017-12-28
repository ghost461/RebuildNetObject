/*
 * Program example of Linked List
 */
//ElementType:Define the type when used.
//Assume use of header node
#ifndef _List_H


struct Node;
struct Information;
typedef struct Node *PtrToNode;
typedef PtrToNode List;
typedef PtrToNode Position;
typedef struct Information* ElementType;

//Make a empty Element(struct Information)
ElementType MakeEmptyElement();
//Return true if two Element are equal
int IsEqual(ElementType X, ElementType Y);
//Set qq_number of Element X
void SetQQnumber(int qq, ElementType X);
//Read qq_number of Element X
int ReadQQnumber(ElementType X);
//Set ip_address of Element X
void SetIPaddress(struct in_addr ip_address, ElementType X);
//Read ip_address of Element X
struct in_addr ReadIPaddress(ElementType X);
//Print the Element(ip_address and qq_number) of X
void printElement(ElementType X);

//Make a empty list
List MakeEmptyList();
//Make a empty node
Position MakeEmptyNode();
//Return true if L is empty
int IsEmpty(List L);
//Return true if P is the last position in list L
int IsLast(Position P, List L);
//Return Position of X in L; NULL if not found
Position Find(ElementType X, List L);
//Delete first occurrence of X from a list
void Delete(ElementType X, List L);
//Find previous of X
Position FindPrevious(ElementType X, List L);
//Insert (after legal position P)
void Insert(ElementType X, List L, Position P);
//Delete list L
void DeleteList(List L);
//Return the position of last node in L
Position Last(List L);
//TODO
Position Header(List L);
//TODO
Position First(List L);
//TODO
Position Advance(Position P);
//TODO
ElementType Retrieve(Position P);

#endif
