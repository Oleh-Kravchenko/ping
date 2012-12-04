CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(ping)

ADD_DEFINITIONS(-pedantic -std=gnu99 -Wall -Werror)

ADD_EXECUTABLE(ping
	main.c
)
