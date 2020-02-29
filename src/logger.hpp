/* Copyright (C) 2020 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#pragma once
#ifndef __LOGGER_HPP
#define __LOGGER_HPP

#include "includes.h"
#include "config.h"

namespace TB {

	class DBGLogger {

	public:
		enum class m_loggerType { DBG_LOGGER_ERROR, DBG_LOGGER_WARNING, DBG_LOGGER_INFO };

		explicit DBGLogger(const char* m_threadBoatVersion, const char* m_fileName)
			: m_warningCount(0U),
			m_errorCount(0U)
		{
			m_logFile.open(m_fileName);

			if (m_logFile.is_open()) { m_logFile << "ThreadBoat Version: " << m_threadBoatVersion << '\n'; }
		}

		~DBGLogger()
		{
			if (m_logFile.is_open())
			{
				m_logFile << std::endl << std::endl;

				m_logFile << m_warningCount << " :: warnings\n";
				m_logFile << m_errorCount << " :: errors\n";

				m_logFile.close();
			}
		}

		friend DBGLogger& operator << (DBGLogger& m_logger, const m_loggerType m_type)
		{
			switch (m_type) {
			case DBGLogger::m_loggerType::DBG_LOGGER_ERROR:
				m_logger.m_logFile << "[ERROR]: ";
				++m_logger.m_errorCount;
				break;

			case DBGLogger::m_loggerType::DBG_LOGGER_WARNING:
				m_logger.m_logFile << "[WARNING]: ";
				++m_logger.m_warningCount;
				break;

			case DBGLogger::m_loggerType::DBG_LOGGER_INFO:
				m_logger.m_logFile << "[INFO]: ";
				break;
			}
			return m_logger;
		}

		friend DBGLogger& operator << (DBGLogger& m_logger, const char* m_fileText)
		{
			m_logger.m_logFile << m_fileText << std::endl;
			return m_logger;
		}

		friend DBGLogger& operator << (DBGLogger& m_logger, DWORD dwOpt)
		{
			m_logger.m_logFile << dwOpt << std::endl;
		}

		DBGLogger(const DBGLogger&) = delete;
		DBGLogger& operator = (const DBGLogger&) = delete;

	private:
		std::ofstream m_logFile;
		unsigned int m_warningCount;
		unsigned int m_errorCount;

	};

}



#endif 