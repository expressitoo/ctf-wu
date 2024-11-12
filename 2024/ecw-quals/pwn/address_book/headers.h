typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;

struct entry;

struct manage_fns_t {
	void (*print_xml)(struct entry *, int);
	void (*update)(struct entry *);
	void (*remove)(struct entry **, struct entry *);
};

struct person_t {
	char address[100];
	char phone_num[16];
	void (*print)(struct entry*);
	struct manage_fns_t *manage_fns;
};

struct shop_t {
	char address[100];
	char phone_num[16];
	char open_time[50];
	char business[22];
	void (*print)(struct entry*);
	struct manage_fns_t* manage_fns;
};

struct hospital_t {
	char director[100];
	char address[100];
	char phone_num[16];
	char open_time[50];
	uint16_t surface;
	uint16_t total_bed;
	uint16_t emergency_bed;
	uint16_t operating_rooms;
	char awards[30];
	uint16_t nb_cured;
	uint16_t nb_dead;
	uint16_t nb_lost;
	void (*print)(struct entry*);
	struct manage_fns_t* manage_fns;
};

struct police_station_t {
	char address[100];
	char phone_num[16];
	char open_time[50];
	uint16_t nb_policeman;
	void (*print)(struct entry*);
	struct manage_fns_t* manage_fns;
};

struct fire_station_t {
	char address[100];
	char phone_num[16];
	uint16_t nb_fireman;
	uint16_t nb_trucks;
	void (*print)(struct entry*);
	struct manage_fns_t* manage_fns;
};

struct association_t {
	char address[100];
	char phone_num[16];
	char purpose[32];
	void (*print)(struct entry*);
	struct manage_fns_t* manage_fns;
};

struct attraction_park_t {
	char director[100];
	char address[100];
	char phone_num[16];
	char open_time[50];
	uint16_t surface;
	uint16_t nb_attraction;
	void (*print)(struct entry*);
	struct manage_fns_t* manage_fns;
};

struct garden_t {
	char address[100];
	uint16_t surface;
	char open_time[50];
	void (*print)(struct entry*);
	struct manage_fns_t* manage_fns;
};

struct entry {
	uint32_t entry_id;
	struct entry* next;
	char name[100];
	union {
		struct person_t person;
		struct shop_t shop;
		struct hospital_t hospital;
		struct police_station_t police_station;
		struct fire_station_t fire_station;
		struct association_t association;
		struct attraction_park_t attraction_park;
		struct garden_t garden;
	};
};

struct entry_type {
	uint32_t entry_type;
	char* name_uppercase;
	char* name_lowercase;
};