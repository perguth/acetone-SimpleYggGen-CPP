#include <iostream>
#include <string>
#include <chrono> //timer

int main()
{
	auto start_time = std::chrono::steady_clock::now(); // timer
	//////////////////////////////////////////////////////////////////////////////////////////////
	//TEST//BEGIN/////////////////////////////////////////////////////////////////////////////////
	
	std::string userInput = "truetext";
	std::string testData = "truearray";
	
	uint8_t userarray[128]; 
	uint8_t testarray[128];
	
	for(int i = 0; i < testData.size(); ++i)
		testarray[i] = testData[i];
	std::cout << "first array" << std::endl;
	
	for(int i = 0; i < userInput.size(); ++i)
		userarray[i] = userInput[i];
	std::cout << "second array" << std::endl;

	int count = 0;
	for(int j = 0; j < 200; ++j)
	{
		for(int i = 0; i < userInput.size(); ++i)
		{
			if(userInput[i] == testData[i])
				++count;
			else break;
		}
	}
	std::cout << count << std::endl;
	
	//TEST//END//////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////
	auto end_time = std::chrono::steady_clock::now();
	auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
	std::cout << "===========" << std::endl <<
	elapsed_ns.count() << " ns\n" << "===========";
}
