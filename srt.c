/*
	Serial Reader Tool version 1.2.0 2019-09-22 by Santtu Nyman.

	Description
		Simple command line tool for reading data from serial port to file.
		Instructions how to use the program are contained in the program.
		
	Version history
		version 1.2.0 2019-09-22
			Added capability to list all available serial port.
		version 1.1.0 2018-10-02
			Added read single burst mode.
		version 1.0.0 2018-08-08
			Added more arguments for controlling the serial port parameters.
		version 0.0.0 2018-08-08
			First publicly available version.

*/

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

BOOL search_argument(SIZE_T argument_count, const WCHAR** argument_values, const WCHAR* short_argument, const WCHAR* long_argument, const WCHAR** value)
{
	for (SIZE_T i = 0; i != argument_count; ++i)
		if ((short_argument && !lstrcmpW(short_argument, argument_values[i])) || (long_argument && !lstrcmpW(long_argument, argument_values[i])))
		{
			if (value)
				*value = i + 1 != argument_count ? argument_values[i + 1] : 0;
			return TRUE;
		}
	if (value)
		*value = 0;
	return FALSE;
}

BOOL decode_integer_string(const WCHAR* string, DWORD* interger)
{
	DWORD result = 0;
	if (*string < L'0' || *string > L'9')
		return FALSE;
	while (*string)
		if (*string >= L'0' || *string <= L'9')
			result = result * 10 + (DWORD)*string++ - (DWORD)L'0';
		else
			return FALSE;
	*interger = result;
	return TRUE;
}

DWORD query_dword_register_value(HKEY root_key, const WCHAR* sub_key_path, const WCHAR* value_name, DWORD* value)
{
	HKEY key;
	DWORD error = (DWORD)RegOpenKeyExW(root_key, sub_key_path, 0, KEY_QUERY_VALUE, &key);
	if (!error)
	{
		DWORD value_type;
		DWORD value_size = sizeof(DWORD);
		DWORD temporal_value;
		error = (DWORD)RegQueryValueExW(key, value_name, 0, &value_type, (BYTE*)&temporal_value, &value_size);
		RegCloseKey(key);
		if (!error)
		{
			if (value_type == REG_DWORD && value_size == sizeof(DWORD))
			{
				*value = temporal_value;
				return 0;
			}
			else
				return ERROR_INVALID_DATATYPE;
		}
	}
	return error;
}

DWORD get_arguments(HANDLE heap, SIZE_T* argument_count, const WCHAR*** argument_values)
{
	DWORD error;
	HMODULE shell32 = LoadLibraryW(L"Shell32.dll");
	if (!shell32)
		return GetLastError();
	SIZE_T local_argument_count = 0;
	const WCHAR** local_argument_values = ((const WCHAR** (WINAPI*)(const WCHAR*, int*))GetProcAddress(shell32, "CommandLineToArgvW"))(GetCommandLineW(), (int*)&local_argument_count);
	if (!local_argument_values)
	{
		error = GetLastError();
		FreeLibrary(shell32);
		return error;
	}
	SIZE_T argument_value_data_size = 0;
	for (SIZE_T i = 0; i != local_argument_count; ++i)
		argument_value_data_size += (((SIZE_T)lstrlenW(local_argument_values[i]) + 1) * sizeof(WCHAR));
	WCHAR** argument_buffer = (WCHAR**)HeapAlloc(heap, 0, local_argument_count * sizeof(WCHAR*) + argument_value_data_size);
	if (!argument_buffer)
	{
		error = GetLastError();
		LocalFree((HLOCAL)local_argument_values);
		FreeLibrary(shell32);
		return error;
	}
	for (SIZE_T w = local_argument_count * sizeof(WCHAR*), i = 0; i != local_argument_count; ++i)
	{
		WCHAR* p = (WCHAR*)((UINT_PTR)argument_buffer + w);
		SIZE_T s = (((SIZE_T)lstrlenW(local_argument_values[i]) + 1) * sizeof(WCHAR));
		argument_buffer[i] = p;
		for (WCHAR* copy_source = (WCHAR*)local_argument_values[i], *copy_source_end = (WCHAR*)((UINT_PTR)copy_source + s), *copy_destination = argument_buffer[i]; copy_source != copy_source_end; ++copy_source, ++copy_destination)
			*copy_destination = *copy_source;
		w += s;
	}
	LocalFree((HLOCAL)local_argument_values);
	FreeLibrary(shell32);
	*argument_count = local_argument_count;
	*argument_values = (const WCHAR**)argument_buffer;
	return 0;
}

DWORD set_file_size(HANDLE file_handle, LARGE_INTEGER size)
{
	LARGE_INTEGER file_pointer;
	file_pointer.LowPart = 0;
	file_pointer.HighPart = 0;
	if (!SetFilePointerEx(file_handle, file_pointer, &file_pointer, FILE_CURRENT))
		return GetLastError();
	if (!SetFilePointerEx(file_handle, size, 0, FILE_BEGIN))
		return GetLastError();
	DWORD error = SetEndOfFile(file_handle) ? 0 : GetLastError();
	if ((file_pointer.LowPart != size.LowPart || file_pointer.HighPart != size.HighPart) && !SetFilePointerEx(file_handle, file_pointer, 0, FILE_BEGIN))
		return error ? error : GetLastError();
	return error;
}

BOOL get_serial_port_number_from_name(const WCHAR* serial_port_name, DWORD* serial_port_number)
{
	SIZE_T length = (SIZE_T)lstrlenW(serial_port_name);
	DWORD port_number = 0;
	DWORD temporal_port_number;
	if (length < 4)
		return 0;
	if ((serial_port_name[0] == L'C' || serial_port_name[0] == L'c') &&
		(serial_port_name[1] == L'O' || serial_port_name[1] == L'o') &&
		(serial_port_name[2] == L'M' || serial_port_name[2] == L'm'))
	{
		for (SIZE_T digit_count = length - 3, digit_index = 0; digit_index != digit_count; ++digit_index)
		{
			if (serial_port_name[3 + digit_index] < L'0' || serial_port_name[3 + digit_index] > L'9')
				return 0;
			temporal_port_number = port_number * 10;
			if (temporal_port_number / 10 != port_number)
				return 0;
			port_number = temporal_port_number;
			temporal_port_number = port_number + (DWORD)(serial_port_name[3 + digit_index] - L'0');
			if (temporal_port_number < port_number)
				return 0;
			port_number = temporal_port_number;
		}
		*serial_port_number = port_number;
		return 1;
	}
	if (length < 8)
		return 0;
	if (serial_port_name[0] == L'\\' &&
		serial_port_name[1] == L'\\' &&
		serial_port_name[2] == L'.' &&
		serial_port_name[3] == L'\\' &&
		(serial_port_name[4] == L'C' || serial_port_name[4] == L'c') &&
		(serial_port_name[5] == L'O' || serial_port_name[5] == L'o') &&
		(serial_port_name[6] == L'M' || serial_port_name[6] == L'm'))
	{
		for (SIZE_T digit_count = length - 7, digit_index = 0; digit_index != digit_count; ++digit_index)
		{
			if (serial_port_name[7 + digit_index] < L'0' || serial_port_name[7 + digit_index] > L'9')
				return 0;
			temporal_port_number = port_number * 10;
			if (temporal_port_number / 10 != port_number)
				return 0;
			port_number = temporal_port_number;
			temporal_port_number = port_number + (DWORD)(serial_port_name[7 + digit_index] - L'0');
			if (temporal_port_number < port_number)
				return 0;
			port_number = temporal_port_number;
		}
		*serial_port_number = port_number;
		return 1;
	}
	return 0;
}

DWORD list_serial_ports(SIZE_T serial_port_number_buffer_length, DWORD* serial_port_number_buffer, SIZE_T* serial_port_count)
{
	const SIZE_T maximum_value_name_length = 16384;
	HANDLE heap = GetProcessHeap();
	if (!heap)
		return ERROR_NOT_ENOUGH_MEMORY;
	SIZE_T value_data_buffer_size = (2048 * sizeof(WCHAR));
	void* value_buffer = HeapAlloc(heap, 0, (maximum_value_name_length * sizeof(WCHAR)) + value_data_buffer_size);
	WCHAR* value_name_buffer = (WCHAR*)value_buffer;
	WCHAR* value_data_buffer = (WCHAR*)((UINT_PTR)value_buffer + (maximum_value_name_length * sizeof(WCHAR)));
	if (!value_buffer)
		return ERROR_NOT_ENOUGH_MEMORY;
	HKEY key;
	DWORD error = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\SERIALCOMM", 0, KEY_QUERY_VALUE, &key);
	if (error)
	{
		HeapFree(heap, 0, value_buffer);
		return error;
	}
	SIZE_T port_count = 0;
	for (DWORD serial_port_number, value_name_leght, value_type, value_data_size, value_index = 0; !error || error == ERROR_MORE_DATA; value_index = error ? value_index : (value_index + 1))
	{
		if (error == ERROR_MORE_DATA)
		{
			value_data_buffer_size = ((((SIZE_T)value_data_size + (sizeof(WCHAR) - 1)) / sizeof(WCHAR)) * sizeof(WCHAR)) + sizeof(WCHAR);
			void* new_value_buffer = (WCHAR*)HeapReAlloc(heap, 0, value_buffer, (maximum_value_name_length * sizeof(WCHAR)) + value_data_buffer_size);
			if (!new_value_buffer)
			{
				RegCloseKey(key);
				HeapFree(heap, 0, value_buffer);
				return ERROR_NOT_ENOUGH_MEMORY;
			}
			value_name_buffer = (WCHAR*)new_value_buffer;
			value_data_buffer = (WCHAR*)((UINT_PTR)new_value_buffer + (maximum_value_name_length * sizeof(WCHAR)));
		}
		else
		{
			value_name_leght = (DWORD)maximum_value_name_length;
			value_data_size = (DWORD)value_data_buffer_size - sizeof(WCHAR);
			error = (DWORD)RegEnumValueW(key, value_index, value_name_buffer, &value_name_leght, 0, &value_type, (BYTE*)value_data_buffer, &value_data_size);
			if (!error && value_type == REG_SZ)
			{
				DWORD value_data_length = (DWORD)(value_data_size / sizeof(WCHAR));
				if (value_data_length)
				{
					if (value_data_buffer[value_data_length - 1] == 0)
						--value_data_length;
					else
						value_data_buffer[value_data_length] = 0;
				}
				else
					*value_name_buffer = 0;
				if (get_serial_port_number_from_name(value_data_buffer, &serial_port_number))
				{
					if (port_count < serial_port_number_buffer_length)
						serial_port_number_buffer[port_count] = serial_port_number;
					++port_count;
				}
			}
		}
	}
	RegCloseKey(key);
	HeapFree(heap, 0, value_buffer);
	if (error != ERROR_NO_MORE_ITEMS)
		return error;
	*serial_port_count = port_count;
	return serial_port_number_buffer_length < port_count ? ERROR_INSUFFICIENT_BUFFER : 0;
}

DWORD create_serial_port_list(HANDLE heap, SIZE_T* serial_port_count, DWORD** serial_port_number_buffer)
{
	SIZE_T buffer_length = 1;
	DWORD* buffer = (DWORD*)HeapAlloc(heap, 0, buffer_length * sizeof(DWORD));
	if (!buffer)
		return ERROR_NOT_ENOUGH_MEMORY;
	DWORD error = ERROR_INSUFFICIENT_BUFFER;
	while (error == ERROR_INSUFFICIENT_BUFFER)
	{
		error = list_serial_ports(buffer_length, buffer, serial_port_count);
		if (error == ERROR_INSUFFICIENT_BUFFER)
		{
			buffer_length = *serial_port_count;
			DWORD* new_buffer = (DWORD*)HeapReAlloc(heap, 0, buffer, buffer_length * sizeof(DWORD));
			if (!buffer)
			{
				HeapFree(heap, 0, buffer);
				return ERROR_NOT_ENOUGH_MEMORY;
			}
			buffer = new_buffer;
		}
	}
	if (!error)
		*serial_port_number_buffer = buffer;
	else
		HeapFree(heap, 0, buffer);
	return error;
}

DWORD open_serial_port(const WCHAR* serial_port_name, DWORD baud_rate, DWORD data_bit_count, DWORD parity, DWORD stop_bit_count, BOOL overlapped, COMMTIMEOUTS* timeouts, HANDLE* serial_port_handle)
{
	if (data_bit_count < 4 || data_bit_count > 8 || parity > 2 || stop_bit_count < 1 || stop_bit_count > 2)
		return ERROR_INVALID_PARAMETER;
	WCHAR serial_port_full_name[16];
	if (serial_port_name[0] == L'\\' && serial_port_name[1] == L'\\' && serial_port_name[2] == L'.' && serial_port_name[3] == L'\\' && serial_port_name[4] == L'C' && serial_port_name[5] == L'O' && serial_port_name[6] == L'M' && serial_port_name[7] >= L'0' && serial_port_name[7] <= L'9')
	{
		SIZE_T port_number_digit_count = 1;
		while (serial_port_name[7 + port_number_digit_count])
			if (serial_port_name[7 + port_number_digit_count] >= L'0' || serial_port_name[7 + port_number_digit_count] <= L'9')
				++port_number_digit_count;
			else
				return ERROR_INVALID_NAME;
		if (port_number_digit_count > 8)
			return ERROR_INVALID_NAME;
		for (WCHAR* r = (WCHAR*)L"\\\\.\\COM", *e = r + 7, *w = serial_port_full_name; r != e; ++r, ++w)
			*w = *r;
		for (WCHAR* r = (WCHAR*)serial_port_name + 7, *e = r + port_number_digit_count + 1, *w = serial_port_full_name + 7; r != e; ++r, ++w)
			*w = *r;
	}
	else if (serial_port_name[0] == L'C' && serial_port_name[1] == L'O' && serial_port_name[2] == L'M' && serial_port_name[3] >= L'0' && serial_port_name[3] <= L'9')
	{
		SIZE_T port_number_digit_count = 1;
		while (serial_port_name[3 + port_number_digit_count])
			if (serial_port_name[3 + port_number_digit_count] >= L'0' || serial_port_name[3 + port_number_digit_count] <= L'9')
				++port_number_digit_count;
			else
				return ERROR_INVALID_NAME;
		if (port_number_digit_count > 8)
			return ERROR_INVALID_NAME;
		for (WCHAR* r = (WCHAR*)L"\\\\.\\COM", *e = r + 7, *w = serial_port_full_name; r != e; ++r, ++w)
			*w = *r;
		for (WCHAR* r = (WCHAR*)serial_port_name + 3, *e = r + port_number_digit_count + 1, *w = serial_port_full_name + 7; r != e; ++r, ++w)
			*w = *r;
	}
	else
		return ERROR_INVALID_NAME;
	HANDLE heap = GetProcessHeap();
	if (!heap)
		return GetLastError();
	DWORD serial_configuration_size = sizeof(COMMCONFIG);
	COMMCONFIG* serial_configuration = (COMMCONFIG*)HeapAlloc(heap, 0, (SIZE_T)serial_configuration_size);
	if (!serial_configuration)
		return GetLastError();
	DWORD error;
	for (BOOL get_serial_configuration = TRUE; get_serial_configuration;)
	{
		DWORD get_serial_configuration_size = serial_configuration_size;
		if (GetDefaultCommConfigW(serial_port_full_name + 4, serial_configuration, &get_serial_configuration_size))
		{
			serial_configuration_size = get_serial_configuration_size;
			get_serial_configuration = FALSE;
		}
		else
		{
			if (get_serial_configuration_size > serial_configuration_size)
			{
				serial_configuration_size = get_serial_configuration_size;
				COMMCONFIG* new_allocation = (COMMCONFIG*)HeapReAlloc(heap, 0, serial_configuration, (SIZE_T)serial_configuration_size);
				if (!new_allocation)
				{
					error = GetLastError();
					HeapFree(heap, 0, serial_configuration);
					return error;
				}
				serial_configuration = new_allocation;
			}
			else
			{
				error = GetLastError();
				HeapFree(heap, 0, serial_configuration);
				return error;
			}
		}
	}
	serial_configuration->dcb.BaudRate = baud_rate;
	serial_configuration->dcb.ByteSize = (BYTE)data_bit_count;
	serial_configuration->dcb.Parity = (BYTE)parity;
	serial_configuration->dcb.StopBits = (stop_bit_count == 1) ? ONESTOPBIT : TWOSTOPBITS;
	serial_configuration->dcb.fDtrControl = DTR_CONTROL_ENABLE;
	COMMTIMEOUTS serial_timeouts = { 0, 0, 0, 0, 0 };
	HANDLE handle = CreateFileW(serial_port_full_name, GENERIC_READ, 0, 0, OPEN_EXISTING, overlapped ? FILE_FLAG_OVERLAPPED : 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		error = GetLastError();
		HeapFree(heap, 0, serial_configuration);
		return error;
	}
	if (!SetupComm(handle, 0x10000, 0x10000) || !SetCommConfig(handle, serial_configuration, serial_configuration_size) || !SetCommTimeouts(handle, timeouts ? timeouts : &serial_timeouts) || !PurgeComm(handle, PURGE_RXCLEAR | PURGE_TXCLEAR))
	{
		error = GetLastError();
		CloseHandle(handle);
		HeapFree(heap, 0, serial_configuration);
		return error;
	}
	HeapFree(heap, 0, serial_configuration);
	Sleep(0x800);
	COMSTAT serial_status;
	DWORD serial_errors;
	ClearCommError(handle, &serial_errors, &serial_status);
	*serial_port_handle = handle;
	return 0;
}

DWORD print(HANDLE console, const WCHAR* string)
{
	if (console != INVALID_HANDLE_VALUE)
	{
		DWORD write_lenght = 0;
		DWORD string_lenght = lstrlenW(string);
		return WriteConsoleW(console, string, string_lenght, &write_lenght, 0) && write_lenght == string_lenght ? 0 : GetLastError();
	}
	return ERROR_INVALID_HANDLE;
}

DWORD print_error(HANDLE console, DWORD error)
{
	SYSTEM_INFO system_info;
	GetNativeSystemInfo(&system_info);
	DWORD print_error;
	SIZE_T format_message_buffer_size = 0x10000;
	WCHAR* error_message = (WCHAR*)VirtualAlloc(0, system_info.dwPageSize ? (((((21 * sizeof(WCHAR)) + format_message_buffer_size) + (system_info.dwPageSize - 1)) / (system_info.dwPageSize)) * system_info.dwPageSize) : ((21 * sizeof(WCHAR)) + format_message_buffer_size), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!error_message)
	{
		format_message_buffer_size = (SIZE_T)system_info.dwPageSize;
		error_message = (WCHAR*)VirtualAlloc(0, system_info.dwPageSize ? (((((21 * sizeof(WCHAR)) + format_message_buffer_size) + (system_info.dwPageSize - 1)) / (system_info.dwPageSize)) * system_info.dwPageSize) : ((21 * sizeof(WCHAR)) + format_message_buffer_size), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!error_message)
			return GetLastError();
	}
	error_message[0] = L'E';
	error_message[1] = L'R';
	error_message[2] = L'R';
	error_message[3] = L'O';
	error_message[4] = L'R';
	error_message[5] = L' ';
	error_message[6] = L'0';
	error_message[7] = L'x';
	for (DWORD index = 0; index != 8; ++index)
		error_message[8 + index] = L"0123456789ABCDEF"[(error >> ((7 - index) << 2)) & 0xF];
	error_message[16] = L' ';
	error_message[17] = L'\"';
	SIZE_T format_message_length = (SIZE_T)FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &error_message[18], (DWORD)(format_message_buffer_size / sizeof(WCHAR)), 0);
	if (!format_message_length)
	{
		print_error = GetLastError();
		VirtualFree(error_message, 0, MEM_RELEASE);
		return print_error;
	}
	while (format_message_length && (error_message[17 + format_message_length] < (WCHAR)0x21))
		--format_message_length;
	error_message[18 + format_message_length] = L'\"';
	error_message[19 + format_message_length] = L'\n';
	error_message[20 + format_message_length] = 0;
	print_error = print(console, error_message);
	VirtualFree(error_message, 0, MEM_RELEASE);
	return print_error;
}

DWORD print_help(HANDLE console)
{
	return print(console,
		L"Program description:\n"
		L"	This tool is used to stream data from a serial port to a file.\n"
		L"	Stop the streaming by pressing CTRL+C.\n"
		L"Parameter List:\n"
		L"	-h or --help Displays help message.\n"
		L"	-p or --serial_port Specifies the serial port which the data is streamed from.\n"
		L"	-b or --baud_rate Specifies the bound rate for the serial port. If this argument is not given, bound rate is set to 9600.\n"
		L"	-o or --output Specifies the ouput file which the data will be streamed to. If no output file is specified the data will be streamed to console.\n"
		L"	-f or --flush_rate Specifies time in seconds which the data is flushed to output. This parameter is ignored if type of the output file is not FILE_TYPE_DISK\n"
		L"	-a or --append If this argument is given the data is appended to end of output file. This parameter is ignored if type of the output file is not FILE_TYPE_DISK\n"
		L"	--buffer_size Recommended size for programs buffer where, data is stored between reading it from the serial port and writing it to the output file.\n"
		L"	--data_bit_count Specifies data bit count for the serial port. If this argument is not given, data bit count is set to 8.\n"
		L"	--parity Specifies parity(0 or N is no parity, 1 or O is odd, 2 or E is even) for the serial port. If this argument is not given, parity is set to no parity.\n"
		L"	--stop_bit_count Specifies stop bit count for the serial port. This value can be 1 or 2. If this argument is not given, stop bit count is set to 1.\n"
		L"	--single_data_burst If this argument is given program stops streaming after reading single data burst from the serial port.\n"
		L"	--list_ports If this argument is given program lists all available serial port. No data is read from any ports when ports are listed.\n");
}

typedef struct configuration_t
{
	HANDLE heap;
	DWORD flush_rate;
	DWORD baud_rate;
	DWORD data_bit_count;
	DWORD parity;
	DWORD stop_bit_count;
	WCHAR* serial_port_name;
	WCHAR* output_file_name;
	HANDLE console_output;
	HANDLE main_thread;
	SIZE_T buffer_size;
	SYSTEM_INFO system_info;
	BOOL append_to_output;
	BOOL single_data_burst;
	BOOL list_ports;
	BOOL help;
	BOOL output_is_console;
} configuration_t;

DWORD get_process_configuration(configuration_t** process_configuration)
{
	const WCHAR* console_output_name = L"CONOUT$";
	const SIZE_T configuration_structure_size = (sizeof(configuration_t) + (sizeof(UINT_PTR) - 1)) & ~(sizeof(UINT_PTR) - 1);
	DWORD default_baud_rate = 9600;
	DWORD default_data_bit_count = 8;
	DWORD default_parity = 0;
	DWORD default_stop_bit_count = 1;
	DWORD default_flush_rate = 0;
	DWORD default_buffer_size = 0x10000;
	DWORD accept_short_argumets = 0;
	query_dword_register_value(HKEY_CURRENT_USER, L"Software\\Santtu Nyman\\srt", L"default_baud_rate", &default_baud_rate);
	query_dword_register_value(HKEY_CURRENT_USER, L"Software\\Santtu Nyman\\srt", L"default_data_bit_count", &default_data_bit_count);
	query_dword_register_value(HKEY_CURRENT_USER, L"Software\\Santtu Nyman\\srt", L"default_parity", &default_parity);
	query_dword_register_value(HKEY_CURRENT_USER, L"Software\\Santtu Nyman\\srt", L"default_stop_bit_count", &default_stop_bit_count);
	query_dword_register_value(HKEY_CURRENT_USER, L"Software\\Santtu Nyman\\srt", L"default_flush_rate", &default_flush_rate);
	query_dword_register_value(HKEY_CURRENT_USER, L"Software\\Santtu Nyman\\srt", L"default_buffer_size", &default_buffer_size);
	query_dword_register_value(HKEY_CURRENT_USER, L"Software\\Santtu Nyman\\srt", L"accept_short_argumets", &accept_short_argumets);
	HANDLE heap = GetProcessHeap();
	if (!heap)
		return GetLastError();
	HANDLE main_thread = OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
	if (!main_thread)
		return GetLastError();
	SIZE_T argc;
	const WCHAR** argv;
	DWORD error = get_arguments(heap, &argc, &argv);
	if (error)
	{
		CloseHandle(main_thread);
		return error;
	}
	BOOL list_ports = search_argument(argc, argv, 0, L"--list_ports", 0);
	DWORD baud_rate = default_baud_rate;
	const WCHAR* baud_rate_string;
	search_argument(argc, argv, L"-b", L"--baud_rate", &baud_rate_string);
	if (baud_rate_string && !decode_integer_string(baud_rate_string, &baud_rate))
	{
		error = ERROR_BAD_ARGUMENTS;
		HeapFree(heap, 0, (LPVOID)argv);
		CloseHandle(main_thread);
		return error;
	}
	DWORD data_bit_count = default_data_bit_count;
	const WCHAR* data_bit_count_string;
	search_argument(argc, argv, 0, L"--data_bit_count", &data_bit_count_string);
	if (data_bit_count_string && (!decode_integer_string(data_bit_count_string, &data_bit_count) || data_bit_count < 4 || data_bit_count > 8))
	{
		error = ERROR_BAD_ARGUMENTS;
		HeapFree(heap, 0, (LPVOID)argv);
		CloseHandle(main_thread);
		return error;
	}
	DWORD parity = default_parity;
	const WCHAR* parity_string;
	search_argument(argc, argv, 0, L"--parity", &parity_string);
	if (parity_string)
	{
		if (!lstrcmpiW(parity_string, L"N"))
			parity = 0;
		else if (!lstrcmpiW(parity_string, L"O"))
			parity = 1;
		else if (!lstrcmpiW(parity_string, L"E"))
			parity = 2;
		else if (!decode_integer_string(parity_string, &parity) || parity > 2)
		{
			error = ERROR_BAD_ARGUMENTS;
			HeapFree(heap, 0, (LPVOID)argv);
			CloseHandle(main_thread);
			return error;
		}
	}
	DWORD stop_bit_count = default_stop_bit_count;
	const WCHAR* stop_bit_count_string;
	search_argument(argc, argv, 0, L"--stop_bit_count", &stop_bit_count_string);
	if (stop_bit_count_string && (!decode_integer_string(stop_bit_count_string, &stop_bit_count) || stop_bit_count < 1 || stop_bit_count > 2))
	{
		error = ERROR_BAD_ARGUMENTS;
		HeapFree(heap, 0, (LPVOID)argv);
		CloseHandle(main_thread);
		return error;
	}
	DWORD flush_rate = default_flush_rate;
	const WCHAR* flush_rate_string;
	search_argument(argc, argv, L"-f", L"--flush_rate", &flush_rate_string);
	if (flush_rate_string && !decode_integer_string(flush_rate_string, &flush_rate))
	{
		error = ERROR_BAD_ARGUMENTS;
		HeapFree(heap, 0, (LPVOID)argv);
		CloseHandle(main_thread);
		return error;
	}
	DWORD buffer_size = default_buffer_size;
	const WCHAR* buffer_size_string;
	search_argument(argc, argv, 0, L"--buffer_size", &buffer_size_string);
	if (buffer_size_string && !decode_integer_string(buffer_size_string, &buffer_size))
	{
		error = ERROR_BAD_ARGUMENTS;
		HeapFree(heap, 0, (LPVOID)argv);
		CloseHandle(main_thread);
		return error;
	}
	const WCHAR* serial_port_name;
	search_argument(argc, argv, L"-p", L"--serial_port", &serial_port_name);
	BOOL only_serial_port_number = FALSE;
	if (!serial_port_name && accept_short_argumets && argc > 1)
	{
		serial_port_name = argv[1];
		if (serial_port_name[0] == L'\\' && serial_port_name[1] == L'\\' && serial_port_name[2] == L'.' && serial_port_name[3] == L'\\' && serial_port_name[4] == L'C' && serial_port_name[5] == L'O' && serial_port_name[6] == L'M' && serial_port_name[7] >= L'0' && serial_port_name[7] <= L'9')
		{
			SIZE_T port_number_digit_count = 1;
			while (serial_port_name && serial_port_name[7 + port_number_digit_count])
				if (serial_port_name[7 + port_number_digit_count] >= L'0' || serial_port_name[7 + port_number_digit_count] <= L'9')
					++port_number_digit_count;
				else
					serial_port_name = 0;
			if (port_number_digit_count > 8)
				serial_port_name = 0;
		}
		else if (serial_port_name[0] == L'C' && serial_port_name[1] == L'O' && serial_port_name[2] == L'M' && serial_port_name[3] >= L'0' && serial_port_name[3] <= L'9')
		{
			SIZE_T port_number_digit_count = 1;
			while (serial_port_name && serial_port_name[3 + port_number_digit_count])
				if (serial_port_name[3 + port_number_digit_count] >= L'0' || serial_port_name[3 + port_number_digit_count] <= L'9')
					++port_number_digit_count;
				else
					serial_port_name = 0;
			if (port_number_digit_count > 8)
				serial_port_name = 0;
		}
		else if (serial_port_name[0] >= L'0' && serial_port_name[0] <= L'9')
		{
			SIZE_T port_number_digit_count = 1;
			while (serial_port_name && serial_port_name[port_number_digit_count])
				if (serial_port_name[port_number_digit_count] >= L'0' || serial_port_name[port_number_digit_count] <= L'9')
					++port_number_digit_count;
				else
					serial_port_name = 0;
			if (port_number_digit_count > 8)
				serial_port_name = 0;
			if (serial_port_name)
				only_serial_port_number = TRUE;
		}
		else
			serial_port_name = 0;
	}
	if (!serial_port_name)
	{
		if (list_ports)
			serial_port_name = L"";
		else
		{
			error = ERROR_BAD_ARGUMENTS;
			HeapFree(heap, 0, (LPVOID)argv);
			CloseHandle(main_thread);
			return error;
		}
	}
	const WCHAR* output_file_name;
	if (!search_argument(argc, argv, L"-o", L"--output", &output_file_name))
		output_file_name = console_output_name;
	else if (!output_file_name)
	{
		if (list_ports)
			serial_port_name = L"";
		else
		{
			error = ERROR_BAD_ARGUMENTS;
			HeapFree(heap, 0, (LPVOID)argv);
			CloseHandle(main_thread);
			return error;
		}
	}
	BOOL append = search_argument(argc, argv, L"-a", L"--append", 0);
	BOOL single_data_burst = search_argument(argc, argv, 0, L"--single_data_burst", 0);
	BOOL help = search_argument(argc, argv, L"-h", L"--help", 0);
	SIZE_T serial_port_name_size;
	if (only_serial_port_number)
		serial_port_name_size = 8 + (SIZE_T)lstrlenW(serial_port_name);
	else
		serial_port_name_size = serial_port_name ? (SIZE_T)lstrlenW(serial_port_name) + 1 : 0;
	SIZE_T output_file_name_size = (SIZE_T)lstrlenW(output_file_name) + 1;
	configuration_t* configuration = (configuration_t*)HeapAlloc(heap, 0, configuration_structure_size + ((serial_port_name_size + output_file_name_size) * sizeof(WCHAR)));
	if (!configuration)
	{
		error = GetLastError();
		HeapFree(heap, 0, (LPVOID)argv);
		CloseHandle(main_thread);
		return error;
	}
	configuration->heap = heap;
	configuration->flush_rate = flush_rate;
	configuration->baud_rate = baud_rate;
	configuration->data_bit_count = data_bit_count;
	configuration->parity = parity;
	configuration->stop_bit_count = stop_bit_count;
	configuration->serial_port_name = serial_port_name_size ? (WCHAR*)((UINT_PTR)configuration + configuration_structure_size) : 0;
	configuration->output_file_name = (WCHAR*)((UINT_PTR)configuration + configuration_structure_size + (serial_port_name_size * sizeof(WCHAR)));
	configuration->console_output = CreateFileW(console_output_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	configuration->main_thread = main_thread;
	configuration->buffer_size = (SIZE_T)buffer_size;
	GetNativeSystemInfo(&configuration->system_info);
	configuration->append_to_output = append;
	configuration->single_data_burst = single_data_burst;
	configuration->list_ports = list_ports;
	configuration->help = help;
	configuration->output_is_console = (BOOL)!lstrcmpiW(output_file_name, console_output_name);
	if (configuration->serial_port_name)
		if (only_serial_port_number)
		{
			for (WCHAR* r = (WCHAR*)L"\\\\.\\COM", *w = (WCHAR*)configuration->serial_port_name, *e = r + 7; r != e; ++r, ++w)
				*w = *r;
			for (WCHAR* r = (WCHAR*)serial_port_name, *w = (WCHAR*)configuration->serial_port_name + 7, *e = r + serial_port_name_size - 7; r != e; ++r, ++w)
				*w = *r;
		}
		else
			for (WCHAR* r = (WCHAR*)serial_port_name, * w = (WCHAR*)configuration->serial_port_name, * e = r + serial_port_name_size; r != e; ++r, ++w)
				*w = *r;
	for (WCHAR* r = (WCHAR*)output_file_name, * w = (WCHAR*)configuration->output_file_name, * e = r + output_file_name_size; r != e; ++r, ++w)
		*w = *r;
	HeapFree(heap, 0, (LPVOID)argv);
	*process_configuration = (configuration_t*)configuration;
	return 0;
}

void free_configuration(configuration_t* configuration)
{
	if (configuration->console_output != INVALID_HANDLE_VALUE)
		CloseHandle(configuration->console_output);
	CloseHandle(configuration->main_thread);
	HeapFree(configuration->heap, 0, (LPVOID)configuration);
}

typedef struct asynchronous_io_t
{
	OVERLAPPED overlapped;
	DWORD error;
	DWORD bytes_transfered;
	BOOL operation_completed;
	BOOL operation_queued;
} asynchronous_io_t;

void CALLBACK ctr_c_close_process_routine(ULONG_PTR parameter)
{
	*(volatile BOOL*)parameter = TRUE;
}

BOOL WINAPI console_handler_routine(DWORD control_signal_type)
{
	if (control_signal_type == CTRL_C_EVENT)
	{
		WCHAR handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + 2 * sizeof(HANDLE) + 1];
		DWORD handler_info_text_lenght = GetEnvironmentVariableW(L"SRT_CTRL_C_EVENT_HANDLER_DATA", handler_info_text_buffer, sizeof(handler_info_text_buffer) / sizeof(WCHAR));
		if (handler_info_text_lenght == sizeof(handler_info_text_buffer) / sizeof(WCHAR) - 1 && handler_info_text_buffer[2 * sizeof(ULONG_PTR)] == L'-' && !handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + 2 * sizeof(HANDLE)])
		{
			ULONG_PTR parameter = 0;
			for (int i = 0; i != 2 * sizeof(ULONG_PTR); ++i)
				parameter = (parameter << 4) | (ULONG_PTR)((L'A' > handler_info_text_buffer[i] ? handler_info_text_buffer[i] - L'0' : 0xA + handler_info_text_buffer[i] - L'A') & 0xF);
			HANDLE thread = 0;
			for (int i = 0; i != 2 * sizeof(HANDLE); ++i)
				thread = (HANDLE)(((UINT_PTR)thread << 4) | (UINT_PTR)((L'A' > handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + i] ? handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + i] - L'0' : 0xA + handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + i] - L'A') & 0xF));
			QueueUserAPC(ctr_c_close_process_routine, thread, parameter);
		}
		return TRUE;
	}
	else
		return FALSE;
}

DWORD set_srt_ctrl_c_event_handler_data(HANDLE main_thread, volatile BOOL* ctrl_c_event_address)
{
	WCHAR handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + 2 * sizeof(HANDLE) + 1];
	for (int i = 0; i != 2 * sizeof(ULONG_PTR); ++i)
		handler_info_text_buffer[i] = "0123456789ABCDEF"[((ULONG_PTR)ctrl_c_event_address >> (ULONG_PTR)(((2 * sizeof(ULONG_PTR) - 1) - i) << 2)) & 0xF];
	handler_info_text_buffer[2 * sizeof(ULONG_PTR)] = L'-';
	for (int i = 0; i != 2 * sizeof(HANDLE); ++i)
		handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + i] = "0123456789ABCDEF"[((UINT_PTR)main_thread >> (UINT_PTR)(((2 * sizeof(HANDLE) - 1) - i) << 2)) & 0xF];
	handler_info_text_buffer[2 * sizeof(ULONG_PTR) + 1 + 2 * sizeof(HANDLE)] = 0;
	if (!SetEnvironmentVariableW(L"SRT_CTRL_C_EVENT_HANDLER_DATA", handler_info_text_buffer))
		return GetLastError();
	if (!SetConsoleCtrlHandler(console_handler_routine, TRUE))
	{
		DWORD error = GetLastError();
		SetEnvironmentVariableW(L"SRT_CTRL_C_EVENT_HANDLER_DATA", 0);
		return error;
	}
	return 0;
}

void WINAPI asynchronous_io_completion_routine(DWORD error, DWORD bytes_transfered, OVERLAPPED* overlapped)
{
	volatile asynchronous_io_t* asynchronous_io = (volatile asynchronous_io_t*)overlapped->hEvent;
	asynchronous_io->error = error;
	asynchronous_io->bytes_transfered = bytes_transfered;
	asynchronous_io->operation_completed = TRUE;
}

SIZE_T read_buffer(BYTE* buffer, SIZE_T size, BYTE* buffer_read, BYTE* buffer_write)
{
	if ((UINT_PTR)buffer_read > (UINT_PTR)buffer_write)
		return (SIZE_T)(((UINT_PTR)buffer + (UINT_PTR)size) - (UINT_PTR)buffer_read);
	else
		return (SIZE_T)((UINT_PTR)buffer_write - (UINT_PTR)buffer_read);
}

SIZE_T write_buffer(BYTE* buffer, SIZE_T size, BYTE* buffer_read, BYTE* buffer_write)
{
	UINT_PTR maximum_buffer_write = (UINT_PTR)buffer_read;
	if (maximum_buffer_write != (UINT_PTR)buffer)
		--maximum_buffer_write;
	else
		maximum_buffer_write = (UINT_PTR)buffer + size - 1;
	if ((UINT_PTR)buffer_write > maximum_buffer_write)
		return (SIZE_T)(((UINT_PTR)buffer + (UINT_PTR)size) - (UINT_PTR)buffer_write);
	else
		return (SIZE_T)((UINT_PTR)maximum_buffer_write - (UINT_PTR)buffer_write);
}

DWORD print_available_serial_ports(HANDLE output)
{
	HANDLE heap = GetProcessHeap();
	if (!heap)
		return ERROR_NOT_ENOUGH_MEMORY;
	WCHAR port_name_buffer[16];
	SIZE_T port_count;
	DWORD* port_number_buffer;
	DWORD error = create_serial_port_list(heap, &port_count, &port_number_buffer);
	if (error)
		return error;
	if (port_count)
	{
		port_name_buffer[0] = L'C';
		port_name_buffer[1] = L'O';
		port_name_buffer[2] = L'M';
		for (SIZE_T port_index = 0; port_index != port_count; ++port_index)
		{
			DWORD port_number = port_number_buffer[port_index];
			SIZE_T port_number_length = 0;
			do
			{
				for (WCHAR* move = port_name_buffer + 3 + port_number_length++; move != port_name_buffer + 3; --move)
					*move = *(move - 1);
				port_name_buffer[3] = L'0' + (WCHAR)(port_number % 10);
				port_number /= 10;
			} while (port_number);
			port_name_buffer[3 + port_number_length] = L'\n';
			port_name_buffer[3 + port_number_length + 1] = 0;
			print(output, port_name_buffer);
		}
	}
	else
		print(output, L"No available serial ports found\n");
	HeapFree(heap, 0, port_number_buffer);
	return 0;
}

int main()
{
	configuration_t* configuration;
	DWORD error = get_process_configuration(&configuration);
	if (error == ERROR_BAD_ARGUMENTS || (!error && configuration->help))
	{
		if (!error)
		{
			print_help(configuration->console_output);
			free_configuration(configuration);
		}
		else
		{
			HANDLE error_console_output = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
			if (error_console_output != INVALID_HANDLE_VALUE)
			{
				print_help(error_console_output);
				CloseHandle(error_console_output);
			}
			else
				ExitProcess((UINT)GetLastError());
		}
		ExitProcess(0);
	}
	if (error)
		ExitProcess((UINT)error);
	if (configuration->list_ports)
	{
		error = print_available_serial_ports(configuration->console_output);
		if (error)
		{
			print(configuration->console_output, L"Unable to list available serial ports. ");
			print_error(configuration->console_output, error);
		}
		free_configuration(configuration);
		ExitProcess((UINT)error);
	}
	volatile BOOL exit_event = FALSE;
	if (configuration->console_output != INVALID_HANDLE_VALUE)
	{
		error = set_srt_ctrl_c_event_handler_data(configuration->main_thread, &exit_event);
		if (error)
		{
			print(configuration->console_output, L"Unable to set console control handler. ");
			print_error(configuration->console_output, error);
			free_configuration(configuration);
			ExitProcess((UINT)error);
		}
	}
	SIZE_T buffer_size = configuration->buffer_size;
	if (buffer_size < (SIZE_T)configuration->system_info.dwPageSize)
		buffer_size = (SIZE_T)configuration->system_info.dwPageSize;
	BYTE* buffer = (BYTE*)HeapAlloc(configuration->heap, 0, buffer_size);
	if (!buffer)
	{
		error = GetLastError();
		print(configuration->console_output, L"Memory allocation failed. ");
		print_error(configuration->console_output, error);
		free_configuration(configuration);
		ExitProcess((UINT)error);
	}
	BYTE* buffer_read = buffer;
	BYTE* buffer_write = buffer;
	HANDLE output = CreateFileW(configuration->output_file_name, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_FLAG_OVERLAPPED, 0);
	if (output == INVALID_HANDLE_VALUE)
	{
		error = GetLastError();
		print(configuration->console_output, L"Unable to open \"");
		print(configuration->console_output, configuration->output_file_name);
		print(configuration->console_output, L"\". ");
		print_error(configuration->console_output, error);
		print_help(configuration->console_output);
		HeapFree(configuration->heap, 0, buffer);
		free_configuration(configuration);
		ExitProcess((UINT)error);
	}
	DWORD output_file_type = GetFileType(output);
	if (output_file_type == FILE_TYPE_DISK && !configuration->append_to_output)
	{
		LARGE_INTEGER zero_file_size;
		zero_file_size.LowPart = 0;
		zero_file_size.HighPart = 0;
		error = set_file_size(output, zero_file_size);
		if (error)
		{
			print(configuration->console_output, L"Unable to truncate \"");
			print(configuration->console_output, configuration->output_file_name);
			print(configuration->console_output, L"\". ");
			print_error(configuration->console_output, error);
			CloseHandle(output);
			HeapFree(configuration->heap, 0, buffer);
			free_configuration(configuration);
			ExitProcess((UINT)error);
		}
	}
	HANDLE input;
	error = open_serial_port(configuration->serial_port_name, configuration->baud_rate, configuration->data_bit_count, configuration->parity, configuration->stop_bit_count, TRUE, 0, &input);
	if (error)
	{
		print(configuration->console_output, L"Unable to open \"");
		print(configuration->console_output, configuration->serial_port_name);
		print(configuration->console_output, L"\". ");
		print_error(configuration->console_output, error);
		CloseHandle(output);
		HeapFree(configuration->heap, 0, buffer);
		free_configuration(configuration);
		ExitProcess((UINT)error);
	}
	print(configuration->console_output, L"Streaming from \"");
	print(configuration->console_output, configuration->serial_port_name);
	print(configuration->console_output, L"\" to \"");
	print(configuration->console_output, configuration->output_file_name);
	print(configuration->console_output, L"\".\n");
	const DWORD data_burst_idle_limit = 256;
	BOOL reading_data_burst = FALSE;
	DWORD last_data_burst_read = 0;
	DWORD flush_rate_ms = configuration->flush_rate ? (configuration->flush_rate * 1000) : INFINITE;
	DWORD wait_ms = configuration->single_data_burst ? data_burst_idle_limit : flush_rate_ms;
	DWORD previous_flush_time = configuration->flush_rate ? GetTickCount() : 0;
	BOOL unflushed_output = FALSE;
	volatile asynchronous_io_t asynchronous_read;
	asynchronous_read.operation_completed = FALSE;
	asynchronous_read.operation_queued = FALSE;
	volatile asynchronous_io_t asynchronous_write;
	asynchronous_write.operation_completed = FALSE;
	asynchronous_write.operation_queued = FALSE;
	while (!error && (!exit_event || read_buffer(buffer, buffer_size, buffer_read, buffer_write)))
	{
		if (!error && !exit_event && !asynchronous_read.operation_queued)
		{
			SIZE_T read_maximum_size = write_buffer(buffer, buffer_size, buffer_read, buffer_write);
			if (read_maximum_size)
			{
				asynchronous_read.overlapped.Internal = 0;
				asynchronous_read.overlapped.InternalHigh = 0;
				asynchronous_read.overlapped.Offset = 0;
				asynchronous_read.overlapped.OffsetHigh = 0;
				asynchronous_read.overlapped.hEvent = (HANDLE)&asynchronous_read;
				asynchronous_read.error = ERROR_UNIDENTIFIED_ERROR;
				asynchronous_read.bytes_transfered = 0;
				asynchronous_read.operation_completed = FALSE;
				asynchronous_read.operation_queued = TRUE;
				ReadFileEx(input, buffer_write, 1, (OVERLAPPED*)&asynchronous_read.overlapped, asynchronous_io_completion_routine);
				error = GetLastError();
				if (error)
					asynchronous_read.operation_queued = FALSE;
			}
		}
		if (!error && !asynchronous_write.operation_queued)
		{
			SIZE_T read_maximum_size = read_buffer(buffer, buffer_size, buffer_read, buffer_write);
			if (read_maximum_size)
			{
				asynchronous_write.overlapped.Internal = 0;
				asynchronous_write.overlapped.InternalHigh = 0;
				if (output_file_type == FILE_TYPE_DISK)
				{
					asynchronous_write.overlapped.Offset = 0xFFFFFFFF;
					asynchronous_write.overlapped.OffsetHigh = 0xFFFFFFFF;
				}
				else
				{
					asynchronous_write.overlapped.Offset = 0;
					asynchronous_write.overlapped.OffsetHigh = 0;
				}
				asynchronous_write.overlapped.hEvent = (HANDLE)&asynchronous_write;
				asynchronous_write.error = ERROR_UNIDENTIFIED_ERROR;
				asynchronous_write.bytes_transfered = 0;
				asynchronous_write.operation_completed = FALSE;
				asynchronous_write.operation_queued = TRUE;
				WriteFileEx(output, buffer_read, read_maximum_size < 0x10000 ? (DWORD)read_maximum_size : 0x10000, (OVERLAPPED*)&asynchronous_write.overlapped, asynchronous_io_completion_routine);
				error = GetLastError();
				if (error)
					asynchronous_write.operation_queued = FALSE;
			}
		}
		if (!error)
		{
			DWORD sleep_result = SleepEx(wait_ms, TRUE);
			if (sleep_result == WAIT_IO_COMPLETION)
			{
				if (!error && asynchronous_read.operation_completed)
				{
					error = asynchronous_read.error;
					if (!error)
					{
						buffer_write += (SIZE_T)asynchronous_read.bytes_transfered;
						if (buffer_write == buffer + buffer_size)
							buffer_write = buffer;
						asynchronous_read.operation_completed = FALSE;
						asynchronous_read.operation_queued = FALSE;
						if (configuration->single_data_burst && !reading_data_burst && asynchronous_read.bytes_transfered)
						{
							reading_data_burst = TRUE;
							last_data_burst_read = GetTickCount();
						}
					}
				}
				if (!error && asynchronous_write.operation_completed)
				{
					error = asynchronous_write.error;
					if (!error)
					{
						buffer_read += (SIZE_T)asynchronous_write.bytes_transfered;
						if (buffer_read == buffer + buffer_size)
							buffer_read = buffer;
						asynchronous_write.operation_completed = FALSE;
						asynchronous_write.operation_queued = FALSE;
						if (output_file_type == FILE_TYPE_DISK || output_file_type == FILE_TYPE_PIPE)
							unflushed_output = TRUE;
					}
				}
			}
			if (!error && flush_rate_ms != INFINITE && unflushed_output)
			{
				DWORD current_time = GetTickCount();
				if (sleep_result != WAIT_IO_COMPLETION || current_time - previous_flush_time >= flush_rate_ms)
				{
					previous_flush_time = current_time;
					if (FlushFileBuffers(output))
						unflushed_output = FALSE;
					else
						error = GetLastError();
				}
			}
			if (configuration->single_data_burst && reading_data_burst && !exit_event)
			{
				DWORD current_time = GetTickCount();
				if (current_time - last_data_burst_read >= data_burst_idle_limit)
					exit_event = TRUE;
				last_data_burst_read = current_time;
			}
		}
	}
	if (asynchronous_read.operation_queued && !asynchronous_read.operation_completed)
	{
		CancelIo(input);
		SleepEx(INFINITE, TRUE);
	}
	if (asynchronous_write.operation_queued && !asynchronous_write.operation_completed)
	{
		CancelIo(output);
		SleepEx(INFINITE, TRUE);
		if (asynchronous_write.operation_completed && (output_file_type == FILE_TYPE_DISK || output_file_type == FILE_TYPE_PIPE))
			unflushed_output = TRUE;
	}
	if (unflushed_output)
	{
		DWORD end_flush_error = FlushFileBuffers(output) ? 0 : GetLastError();
		if (!error)
			error = end_flush_error;
	}
	print(configuration->console_output, L"Streaming stopped. ");
	print_error(configuration->console_output, error);
	CloseHandle(input);
	CloseHandle(output);
	HeapFree(configuration->heap, 0, buffer);
	free_configuration(configuration);
	ExitProcess((UINT)error);
	return -1;
}