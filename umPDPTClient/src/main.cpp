#include "conn.h"

int main() {
	auto& driver = umPDPTClient::Driver::GetInstance();
	driver.Connect();

	driver.Map();

	std::this_thread::sleep_for(std::chrono::minutes(10));

	return 0;
}