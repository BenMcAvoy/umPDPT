#include "conn.h"

int main() {
	auto& driver = umPDPTClient::Driver::GetInstance();
	driver.Connect();

	// TODO: Add further client logic here

	return 0;
}