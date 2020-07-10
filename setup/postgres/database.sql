CREATE TABLE prize (
	prize_id VARCHAR(36) PRIMARY KEY, 
	prize VARCHAR(36), 
	created TIMESTAMP
);
CREATE TABLE voucher (
	voucher_id SERIAL PRIMARY KEY, 
	active BOOLEAN 
);

CREATE TABLE "key" (
	"key" VARCHAR(12) PRIMARY KEY, 
	created TIMESTAMP 
);

CREATE TABLE "user" (
	username VARCHAR(36) PRIMARY KEY, 
	password VARCHAR(36), 
	ip VARCHAR(40), 
	code VARCHAR(36), 
	created TIMESTAMP, 
	session VARCHAR(36), 
	active BOOLEAN, 
	coins INTEGER, 
	recruited_by VARCHAR(36), 
	fcode VARCHAR(32), 
	item VARCHAR(128), 
	item_cost INTEGER, 
	items_sold INTEGER, 
	item_sold_ts TIMESTAMP 
);

