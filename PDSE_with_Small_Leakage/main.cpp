#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <cmath>
#include <fstream>
#include <cstdio>
#include <dirent.h> // Dirent API for Microsoft Visual Studio

#include <cstring>
#include <cstdio>
#include <algorithm>
#include <vector>

#include <sha.h>
#include <osrng.h>
#include <hex.h>
#include <hmac.h>
#include <cmac.h>
#include <modes.h>

#define KEY_LENGTH 16
#define KEYWORD_MAX_LENGTH 32

#pragma comment(lib, "cryptlib.lib")

using namespace std;
using namespace CryptoPP;

struct unencoded_data // gamma_L in client
{
	int l_star; // l* 
	char w[KEYWORD_MAX_LENGTH]; // keyword
	int id; // file ID
	int op; // add: 0, del: 1
	int cnt; // counter for a keyword w
};

struct encoded_data //T_l in server
{
	char c1[8]; // encrypt file ID and l_star by XOR, the size of cipher is 8 bytes;
	char c2[64]; // encrypt l_star, keyword w, file ID, OP code, counter by AES_128_ECB, the size of cipher is 64 bytes
};

struct partial_c1 // server can decryption this part by token
{
	int l_star;
	int id;
};

int dec_T_to_gamma(byte *esk, int esk_length, string T_path, struct encoded_data *T, struct unencoded_data *gamma); // decrypt c2 of a encoded data structure T and store to a unencoded data structure gamma

/* operator overloading for struct unencoded_data */
bool operator< (const struct unencoded_data& gamma1, const struct unencoded_data& gamma2)
{
	int status;

	if (gamma1.l_star < gamma2.l_star)
		return true;
	else
	{
		status = strncmp(gamma1.w, gamma2.w, KEYWORD_MAX_LENGTH);
		if (status < 0)
			return true;
		else if (status == 0)
		{
			if (gamma1.id < gamma2.id)
				return true;
			else if (gamma1.id == gamma2.id)
			{
				if (gamma1.op < gamma2.op)
					return true;
				else 
					return false;
			}
			else
				return false;
		}
		else
			return false;
	}
};

ostream& operator<< (ostream& out, const struct unencoded_data gamma)
{
	out << "l*: " << gamma.l_star << endl
		<< "w : " << gamma.w << endl
		<< "id: " << gamma.id << endl
		<< "op: " << gamma.op << endl;

	return out;
};
/* operator overloading for struct unencoded_data */

string sha256(string text)
{
	SHA256 hash;
	//string text = "Test";
	string result;
	string encoded;

	StringSource ss1(text, true,
		new HashFilter(hash,
		new StringSink(result)
		) // HashFilter 
		); // StringSource
	//cout << "DEBUG: result.size() = " << result.size() << endl;
	
	/*
	StringSource ss2(result, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	

	cout << "Data: " << text << endl << "SHA-256 hash: " << encoded << endl;
	*/

	return result;
}

string HMAC_SHA_256(byte *user_key, int user_key_len, string plain)
{
	SecByteBlock key(user_key, user_key_len);
	string mac, encoded;

	/*
	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	cout << "key: " << encoded << endl;
	cout << "plain text: " << plain << endl;
	*/

	try
	{
		HMAC< SHA256 > hmac(key, key.size());

		StringSource ss2(plain, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*
	// Pretty print
	encoded.clear();
	StringSource ss3(mac, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	cout << "hmac: " << encoded << endl;
	*/

	return mac;
}

string CMAC_AES_128(byte *user_key, int user_key_len, string plain) // user_key_len must be equal to AES::DEFAULT_KEYLENGTH
{
	//byte user_key[16] = {0x00};
	SecByteBlock key(user_key, user_key_len);

	//string plain = "CMAC Test";
	string mac, encoded;

	/*
	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	cout << "key: " << encoded << endl;
	cout << "plain text: " << plain << endl;
	*/

	try
	{
		CMAC< AES > cmac(key.data(), key.size());

		StringSource ss2(plain, true,
			new HashFilter(cmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*
	// Pretty print
	encoded.clear();
	StringSource ss3(mac, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	cout << "cmac: " << encoded << endl;
	*/

	return mac;
}

string AES_128_ECB_enc(byte *user_key, int user_key_len, string plain)
{
	SecByteBlock key(user_key, user_key_len);
	
	//string plain = "ECB Mode Test";
	string cipher, encoded;

	try
	{
		//cout << "plain text: " << plain << endl;

		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, key.size());

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource ss1(plain, true,
			new StreamTransformationFilter(e,
			new StringSink(cipher)
			) // StreamTransformationFilter      
			); // StringSource
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*
	// Pretty print cipher text
	StringSource ss2(cipher, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	cout << "cipher text: " << encoded << endl;
	*/

	return cipher;
}

string AES_128_ECB_dec(byte *user_key, int user_key_len, string cipher)
{
	SecByteBlock key(user_key, user_key_len);

	//string plain = "ECB Mode Test";
	string recovered;

	try
	{
		ECB_Mode< AES >::Decryption d;
		// ECB Mode does not use an IV
		d.SetKey(key, key.size());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss3(cipher, true,
			new StreamTransformationFilter(d,
			new StringSink(recovered)
			) // StreamTransformationFilter
			); // StringSource

		//cout << "recovered text: " << recovered << endl;
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	return recovered;
}

inline void string_to_byte(byte *b_text, string s_text, int b_text_len)
{
	memcpy((char*)b_text, s_text.c_str(), b_text_len);
}

inline string hex_encoder(string raw)  // encode raw data to hex string data for showing
{
	string hex;
	StringSource ss2(raw, true,
		new HexEncoder(
		new StringSink(hex)
		) // HexEncoder
		); // StringSource
	return hex;
}

void binary_search()
{

}

int find_l_star(byte *level_key, int level_key_length, byte *esk, int esk_length, int search_level, string w, int id) // for client when op = del
{
	struct encoded_data T;
	struct unencoded_data gamma;

	fstream file_T;
	string T_path;

	int size_L = pow(2, search_level);
	
	char temp = 0; // 0: for computing hkey
	int cnt, op = 0; // op = add, because we want find the "add" location
	
	string keyword_hash = sha256(w);
	string token = CMAC_AES_128(level_key, level_key_length, keyword_hash); // token_l
	string hkey, hex;

	int dec_status;
	
	for (cnt = 0; cnt < size_L; cnt++)
	{
		hkey.assign(&temp, sizeof(temp)); // 0
		hkey.append((char*)&op, sizeof(op)); // 0 || op
		hkey.append((char*)&cnt, sizeof(cnt)); // 0 || op ||cnt
		hkey = HMAC_SHA_256((byte*)token.c_str(), token.size(), hkey); // output data for creating hash table

		hex = hex_encoder(hkey); // output for hash table
		T_path = "./Server/T_" + to_string(search_level) + "[" + hex + "]"; // rename means not empty
		cout << "Try to find: " << T_path << endl;

		dec_status = dec_T_to_gamma(esk, esk_length, T_path, &T, &gamma);
		if (dec_status == 0)
		{
			return gamma.l_star;
		}
		else
			continue;
	}

	return -1; // not found
}

int dec_T_to_gamma(byte *esk, int esk_length, string T_path, struct encoded_data *T, struct unencoded_data *gamma) // decrypt c2 of a encoded data structure T and store to a unencoded data structure gamma
{
	//struct encoded_data T;
	//struct unencoded_data gamma;
	fstream file_T;

	string recoved_string, c2;

	file_T.open(T_path, ios::out | ios::in | ios::binary);
	if (!file_T)
	{
		cerr << "Error: open " << T_path << " failed..." << endl;
		return -1;
	}
	else
	{
		file_T.read((char*)T, sizeof(encoded_data));
		file_T.close();

		//recoved_string = AES_128_ECB_dec(esk, esk_length, T->c2); // 72 bytes, using T -> c2 is not work because T -> c2 is not string
		c2.assign(T->c2, 64); // c2 is 64 bytes
		recoved_string = AES_128_ECB_dec(esk, esk_length, c2);
		string_to_byte((byte*)gamma, recoved_string, sizeof(unencoded_data));
		
		printf("************\n");
		printf("old l* = %d\n", gamma->l_star);
		printf("keyword = %s\n", gamma->w);
		printf("id = %d\n", gamma->id);
		printf("op = %d\n", gamma->op);
		printf("old cnt = %d\n", gamma->cnt);
		printf("************\n");
		
		return 0; // decrypt successfully
	}
}

class PDSE
{
	public:
		
		void setup()
		{
			cout << "Please enter the the number of document-keyword pairs:" << endl << ">>";
			cin >> N;
			cout << "**** Server Message ****" << endl;
			server_setup();
			cout << endl;
			cout << "**** Client Message ****" << endl;
			client_setup();
		}

		void update(string keyword, int id, int op)
		{
			int free_level = -1;
			fstream file_T;
			string T_path;
			
			cout << "**** Download the first entry for each level from server ****" << endl; // just show a message
			/* Check which level is empty */
			cout << "**** Check which level is empty ****" << endl;
			for (int i = 0; i <= L; i++)
			{
				T_path = "./Server/T_" + to_string(i) + "[" + to_string(0) + "]"; // check the first entry for each level
				cout << "Try to find empty entry: " << T_path << endl;
				file_T.open(T_path, ios::in | ios::binary); // Can open the file means free because encode_entry() will rename the level files
				if (!file_T)
				{
					cout << "Level " << i <<" is occupied" << endl;
					free_level = -1;
				}
				else
				{
					cout << "Level " << i << " is free!" << endl;
					free_level = i;
					file_T.close();
					break;
				}
			}
			/* Check which level is empty */
			
			if (free_level < 0)
				cerr << "Error: the server has been full!" << endl;
			else if (free_level == 0)
				encode_entry(free_level, 0, keyword, id, op, 0); // for level, the index and cnt must be 0
			else
				simple_rebuild(free_level, keyword, id, op);
		}

		void search()
		{

		}
	
	private:
		
		int N; // ths size of the document collection, the number of document-keyword pairs
		int L; // maximum level

		byte esk[KEY_LENGTH]; // key esk for encrypt c2
		byte **k; // key for each level for encrypt c1
		
						
		void server_setup()
		{
			L = log2(N); // count the maximum level

			int size_L; // size of the level
			int memory_usage = 0; // count the memory usuage in server
			struct encoded_data T; // the encoded data structure store in server. Using a free T, instead of locating every T for each level to save memory
			//struct encoded_data **T; // for locating every T for each level
			//T = new struct encoded_data*[L + 1];
			memset(&T, -1, sizeof(struct encoded_data));

			fstream T_file;
			string T_path;

			cout << "Maximum level: " << L << endl;

			/*
			for (int i = 0; i < L + 1; i++) // locating every T for each level really
			{
				size_L = pow(2, i);
				cout << "Level " << i << " has the size: " << size_L;
				T[i] = new struct encoded_data[size_L];
				memset(T[i], -1, sizeof(struct encoded_data)*size_L);
				memory_usage = memory_usage + sizeof(struct encoded_data)*size_L;
				cout << endl;
			}
			*/
			
			for (int i = 0; i <= L; i++) // output free T to server, for each level
			{
				size_L = pow(2, i);
				cout << "Level " << i << " has the size: " << size_L << endl;
				memory_usage = memory_usage + sizeof(struct encoded_data)*size_L;
				
				for (int j = 0; j < size_L; j++) // for the index in a level
				{
					T_path = "./Server/T_" + to_string(i) + "[" + to_string(j) + "]";
					T_file.open(T_path, ios::out | ios::binary);
					if (!T_file)
					{
						cerr << "Error: create " << T_path << " failed..." << endl;
						exit(1);
					}
					else
					{
						T_file.write((char*)&T, sizeof(struct encoded_data));
						cout << "Output file: " << T_path << endl;
						T_file.close();
					}						
				}
				cout << endl;
			}
			cout << "Memory usages: " << memory_usage << " bytes" << endl;
		}

		void client_setup()
		{
			memset(esk, 0, KEY_LENGTH);
			cout << "Generate k_esk" << ": ";

			for (int i = 0; i < KEY_LENGTH; i++) // show the key esk
			{
				printf("%d", esk[i]);
			}
			cout << endl;


			k = new byte*[L + 1];

			for (int i = 0; i <= L; i++)
			{
				k[i] = new byte[KEY_LENGTH];
				memset(k[i], i, KEY_LENGTH);
				cout << "Generate k_" << i << ": ";
				for (int j = 0; j < KEY_LENGTH; j++) // show the key k_j for each level i
				{
					printf("%d", k[i][j]);
				}
				cout << endl;
			}
		}

		void encode_entry(int level, int index, string w, int id, int op, int cnt) // w: keyword, index: for a level
		{
			cout << "**** Encode entry store to index " << index << " of the level " << level <<" ****" << endl;

			struct unencoded_data gamma; // create a unencoded data structure to save the document-keyword pair
			memset(&gamma, 0, sizeof(gamma));

			fstream file_T;
			string T_path; // old name
			string new_name; // new name
			
			string buf; // buf for computing hkey and c1
			char temp; // 0: for computing hkey, 1: for computing c1

			/* Store information to unencoded data structure gamma */
			if (op == 0) // for add
				gamma.l_star = level;
			else if (op == 1) // for delete, find the corrsponding "add" document-keyword pair in which level l from server
			{
				// 只要往上層找，因為如果add在下層，那舊的add和新的delete會被移到同一層，然後抵銷 (simple_rebuild處理)
				gamma.l_star = find_l_star(k[level + 1], KEY_LENGTH, esk, KEY_LENGTH, level + 1, w, id); // for client when op = del
				if (gamma.l_star == -1) // not found "add" in server
				{
					cerr << "Erroe: cannot delete because the corrsponding document-keyword pair is not added" << endl;
					return;
				}
			}
			
			strncpy(gamma.w, w.c_str(), w.size());
			gamma.id = id;
			gamma.op = op;
			gamma.cnt = cnt;
			/* Store information to unencoded data structure gamma */

			string keyword_hash = sha256(w);
			string token = CMAC_AES_128(k[level], KEY_LENGTH, keyword_hash); // token_l

			temp = 0; // 0: for computing hkey
			buf.assign(&temp, sizeof(temp));
			buf.append((char*)&gamma.op, sizeof(gamma.op));
			buf.append((char*)&gamma.cnt, sizeof(gamma.cnt));
			string hkey = HMAC_SHA_256((byte*)token.c_str(), token.size(), buf); // output data for creating hash table

			string hex = hex_encoder(hkey); // output for hash table
			new_name = "./Server/T_" +to_string(level) + "[" + hex + "]"; // rename means not empty
						
			string c1; // output data, including l* and file ID, server can decrypt by token
			c1.assign((char*)&gamma.l_star, sizeof(gamma.l_star)); // 4 bytes
			c1.append((char*)&gamma.id, sizeof(gamma.id)); // 4 bytes		
			
			temp = 1;
			buf.assign(&temp, sizeof(temp));
			buf.append((char*)&gamma.op, sizeof(gamma.op));
			buf.append((char*)&gamma.cnt, sizeof(gamma.cnt));
			string temp_key = HMAC_SHA_256((byte*)token.c_str(), token.size(), buf);

			for (int i = 0; i < c1.size(); i++)
			{
				c1[i] = c1[i] ^ temp_key[i];
			}

			string c2; // output data, only client can decrypt by key esk
			c2.assign((char*)&gamma.l_star, sizeof(gamma.l_star));
			c2.append(gamma.w, KEYWORD_MAX_LENGTH);
			c2.append((char*)&gamma.id, sizeof(gamma.id));
			c2.append((char*)&gamma.op, sizeof(gamma.op));
			c2.append((char*)&gamma.cnt, sizeof(gamma.cnt));
			c2 = AES_128_ECB_enc(esk, KEY_LENGTH, c2);

			T_path = "./Server/T_" + to_string(level) + "[" +  to_string(index) + "]";
			cout << "Open: " << T_path << endl;
			file_T.open(T_path, ios::out | ios::in | ios::binary);
			if (!file_T)
			{
				cerr << "Error: open " << T_path << " failed..." << endl;
			}
			else
			{
				cout << "Write encrypted data to " << T_path << endl;
				file_T.write(c1.c_str(), c1.size());
				file_T.write(c2.c_str(), c2.size());
				file_T.close();
				
				cout << "Rename " << T_path << " to " << new_name << endl;
				rename(T_path.c_str(), new_name.c_str());
			}

			/*
			cout << "Decryption Test:" << endl;
			struct encoded_data dec_test_T;
			struct unencoded_data dec_test_gamma;
			dec_T_to_gamma(esk, KEY_LENGTH, new_name, &dec_test_T, &dec_test_gamma);
			*/
		}

		void simple_rebuild(int level, string keyword, int id, int op)
		{
			string T_path;
			
			string dir_path = "./Server";
			DIR *dp;
			struct dirent *ep;

			string compare_name;
			string file_name;
			string free_name;

			int size_L = pow(2, level);

			struct encoded_data T;
			struct unencoded_data *gamma;
			string recoved_string, temp_c2, temp_keyword;

			int gamma_index = 0; // the index for gamma
			int level_index = 0; // the index for each lvele 

			//cout << "**** Prepare " << size_L - 1 << " encoded entry ****" << endl;
			//T = new struct encoded_data[size_L - 1];

			cout << "**** Prepare " << size_L << " unencoded entry ****" << endl;
			gamma = new struct unencoded_data[size_L];
			memset(gamma, 0, sizeof(struct unencoded_data) * size_L);

			cout << "**** Download ALL encoded entry in server which level is lower than " << level << " ****" << endl;
			
			/* Read all download entry to RAM and decryption */
			dp = opendir(dir_path.c_str());
			if (dp != NULL)
			{
				for (int i = 0; i < level; i++)
				{
					cout << "Download encoded entry in level " << i << endl;
					compare_name = "T_" + to_string(i);
					level_index = 0;
					
					while (ep = readdir(dp))
					{
						file_name.assign(ep->d_name);
						if (file_name.find(compare_name, 0) == 0) // find all entry for level i
						{
							//printf("File: %s\n", ep->d_name); // file name
							T_path = dir_path + "/" + ep->d_name;
							cout << "Open: " << T_path << endl;

							if (dec_T_to_gamma(esk, KEY_LENGTH, T_path, &T, &gamma[gamma_index]) == 0) // decrypt encoded data successfully and store to unencoded data structure gamma
							{
								free_name = dir_path + "/" + compare_name + "[" + to_string(level_index) + "]";
								rename(T_path.c_str(), free_name.c_str()); // free the file by rename to origional name
								
								gamma_index++; // for stode to next gamma
								level_index++; // for read next level
							}
						}
					}
					rewinddir(dp);
				}
				closedir(dp);
				/* Read all download entry to RAM and decryption */

				/* Store new entry to the last location in gamma */
				strncpy(gamma[size_L - 1].w, keyword.c_str(), keyword.size());
				gamma[size_L - 1].id = id;
				gamma[size_L - 1].op = op;
				/* Store new entry to the last location in gamma */

				/* Sorting T and gamma by l_star, w, id, op */
				/* Sorting T and gamma by l_star, w, id, op */

				/* Upload each entry to server */
				for (int i = 0; i < size_L; i++)
				{
					//gamma[i].cnt = i; // recount cnt for each level
					temp_keyword.assign(gamma[i].w);
					encode_entry(level, i, temp_keyword, gamma[i].id, gamma[i].op, i);
				}
				/* Upload each entry to server */
			}

			//delete[](T);
			delete[](gamma);
		}

		void process_level()
		{

		}

		void skip_hole()
		{

		}

		void delete_sum()
		{

		}
};

int main()
{
	int opcode, update_op;
	
	string keyword;
	int file_ID;
	
	PDSE pdse_obj;
	cout << "**** System setup ****" << endl;
	pdse_obj.setup();
	
	cout << endl << "Enter OP code:" << endl;
	cout << "	0: Update" << endl;
	cout << "	1: Search" << endl;
	cout << "	Ctrl + Z: Exit" << endl;
	cout << ">>";
	while (cin >> opcode)
	{
		switch (opcode)
		{
			case 0:
				cout << "Which operation you want to do? " << endl;
				cout << "	Enter \"0\" to add a file" << endl;
				cout << "	Enter \"1\" to delete a file" << endl << ">>";
				cin >> update_op;
				if (update_op == 0)
					cout << "Enter the file ID you want to add: " << endl << ">>";
				else if (update_op == 1)
					cout << "Enter the file ID you want to delete: " << endl << ">>";
				else
				{
					cerr << "Error: update opcode is incorrect..." << endl;
					break;
				}
				cin >> file_ID;
				cout << "Enter the keyword includ in the corrsponding file: : " << endl << ">>";
				cin >> keyword;
				if (keyword.size() > 32)
					cerr << "The maximum length for a keyword cannot more than 32 bytes" << endl;
				else
					pdse_obj.update(keyword, file_ID, update_op);
				
				break;

			case 1:
				break;

			default:
				cout << "Opcode is incorrect..." << endl;
		}

		cout << endl << "Enter OP code:" << endl;
		cout << "	0: Update" << endl;
		cout << "	1: Search" << endl;
		cout << "	Ctrl + Z: Exit" << endl;
		cout << ">>";
	}

	system("PAUSE");
	return 0;
}