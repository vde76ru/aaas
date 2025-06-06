<?php
namespace App\Controllers;

use App\Core\Database;
use App\Core\Logger;
use App\Core\Cache;
use App\Core\Config;
use App\Core\Paths;
use App\Core\Env;
use App\Services\AuthService;
use App\Services\MetricsService;
use App\Services\QueueService;
use App\Services\EmailService;
use OpenSearch\ClientBuilder;

/**
 * Полная диагностика системы VDestor B2B
 * Проверяет абсолютно все компоненты и настройки
 */
class DiagnosticsController extends BaseController
{
    private array $diagnostics = [];
    private float $startTime;
    private int $totalChecks = 0;
    private int $passedChecks = 0;
    private int $warningChecks = 0;
    private int $failedChecks = 0;
    private array $criticalErrors = [];

    public function __construct()
    {
        $this->startTime = microtime(true);
    }

    /**
     * GET /api/admin/diagnostics/run - Запустить полную диагностику
     */
    public function runAction(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        
        // Увеличиваем лимиты для диагностики
        set_time_limit(300);
        ini_set('memory_limit', '512M');

        try {
            // === 1. СИСТЕМНЫЕ ПРОВЕРКИ ===
            $this->checkSystemInfo();
            $this->checkPHPConfiguration();
            $this->checkPHPExtensions();
            $this->checkFileSystem();
            $this->checkPermissions();
            $this->checkDiskSpace();
            $this->checkSystemLoad();
            
            // === 2. СЕТЕВЫЕ ПРОВЕРКИ ===
            $this->checkNetworkConnectivity();
            $this->checkDNS();
            $this->checkHTTPS();
            
            // === 3. БАЗА ДАННЫХ ===
            $this->checkDatabase();
            $this->checkDatabaseTables();
            $this->checkDatabaseIndexes();
            $this->checkDatabasePerformance();
            $this->checkDatabaseIntegrity();
            $this->checkDatabaseSize();
            
            // === 4. OPENSEARCH ===
            $this->checkOpenSearch();
            $this->checkOpenSearchIndexes();
            $this->checkOpenSearchPerformance();
            
            // === 5. КЕШ ===
            $this->checkCache();
            $this->checkCachePerformance();
            $this->checkCacheSize();
            
            // === 6. СЕССИИ ===
            $this->checkSessions();
            $this->checkSessionSecurity();
            $this->checkActiveSessions();
            
            // === 7. ОЧЕРЕДИ ===
            $this->checkQueues();
            $this->checkQueueWorkers();
            $this->checkFailedJobs();
            
            // === 8. EMAIL ===
            $this->checkEmailConfiguration();
            $this->checkEmailDelivery();
            
            // === 9. БЕЗОПАСНОСТЬ ===
            $this->checkSecurityHeaders();
            $this->checkFileSecurityPermissions();
            $this->checkConfigurationSecurity();
            $this->checkLoginAttempts();
            $this->checkSuspiciousActivity();
            
            // === 10. ПРОИЗВОДИТЕЛЬНОСТЬ ===
            $this->checkAPIPerformance();
            $this->checkPageLoadTime();
            $this->checkSlowQueries();
            $this->checkMemoryUsage();
            
            // === 11. ЛОГИ И ОШИБКИ ===
            $this->checkErrorLogs();
            $this->checkApplicationLogs();
            $this->checkAccessLogs();
            $this->checkSecurityLogs();
            
            // === 12. ДАННЫЕ И КОНТЕНТ ===
            $this->checkDataIntegrity();
            $this->checkOrphanedRecords();
            $this->checkDuplicateData();
            $this->checkMissingRelations();
            
            // === 13. МЕТРИКИ И СТАТИСТИКА ===
            $this->checkMetrics();
            $this->checkBusinessMetrics();
            $this->checkSystemMetrics();
            
            // === 14. ВНЕШНИЕ СЕРВИСЫ ===
            $this->checkExternalAPIs();
            $this->checkCDNServices();
            
            // === 15. КОНФИГУРАЦИЯ ===
            $this->checkConfiguration();
            $this->checkEnvironmentVariables();
            $this->checkCronJobs();
            
            // === 16. ФРОНТЕНД ===
            $this->checkAssets();
            $this->checkJavaScript();
            $this->checkCSS();
            
            // === ИТОГОВЫЙ ОТЧЕТ ===
            $report = $this->generateReport();
            $this->success($report);

        } catch (\Exception $e) {
            Logger::error('Diagnostics failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            $this->error('Diagnostics failed: ' . $e->getMessage(), 500);
        }
    }

    // === 1. СИСТЕМНЫЕ ПРОВЕРКИ ===

    private function checkSystemInfo(): void
    {
        $this->totalChecks++;
        
        $data = [
            'title' => '🖥️ Информация о системе',
            'status' => '✅ OK',
            'data' => [
                'Hostname' => gethostname(),
                'OS' => php_uname('s') . ' ' . php_uname('r'),
                'Architecture' => php_uname('m'),
                'PHP Version' => PHP_VERSION,
                'PHP SAPI' => PHP_SAPI,
                'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'Server Time' => date('Y-m-d H:i:s'),
                'Timezone' => date_default_timezone_get(),
                'Uptime' => $this->getSystemUptime()
            ]
        ];
        
        // Проверка версии PHP
        if (version_compare(PHP_VERSION, '7.4.0', '<')) {
            $data['status'] = '❌ Error';
            $data['error'] = 'PHP версия ниже 7.4.0';
            $this->failedChecks++;
            $this->criticalErrors[] = 'Устаревшая версия PHP';
        } else {
            $this->passedChecks++;
        }
        
        $this->diagnostics['system'] = $data;
    }

    private function checkPHPConfiguration(): void
    {
        $this->totalChecks++;
        
        $requiredSettings = [
            'memory_limit' => ['required' => '256M', 'compare' => '>='],
            'max_execution_time' => ['required' => 300, 'compare' => '>='],
            'post_max_size' => ['required' => '32M', 'compare' => '>='],
            'upload_max_filesize' => ['required' => '32M', 'compare' => '>='],
            'max_input_vars' => ['required' => 1000, 'compare' => '>='],
            'max_file_uploads' => ['required' => 20, 'compare' => '>=']
        ];
        
        $checks = [];
        $hasErrors = false;
        
        foreach ($requiredSettings as $setting => $requirement) {
            $current = ini_get($setting);
            
            if ($setting === 'max_execution_time' && $current == 0) {
                $checks[$setting] = [
                    'current' => 'Unlimited',
                    'required' => $requirement['required'],
                    'status' => '✅'
                ];
                continue;
            }
            
            $currentBytes = $this->parseSize($current);
            $requiredBytes = $this->parseSize($requirement['required']);
            
            $passed = false;
            switch ($requirement['compare']) {
                case '>=':
                    $passed = $currentBytes >= $requiredBytes;
                    break;
                case '<=':
                    $passed = $currentBytes <= $requiredBytes;
                    break;
            }
            
            $checks[$setting] = [
                'current' => $current,
                'required' => $requirement['required'],
                'status' => $passed ? '✅' : '❌'
            ];
            
            if (!$passed) {
                $hasErrors = true;
            }
        }
        
        // Дополнительные настройки
        $additionalSettings = [
            'display_errors' => ini_get('display_errors'),
            'error_reporting' => error_reporting(),
            'log_errors' => ini_get('log_errors'),
            'error_log' => ini_get('error_log'),
            'date.timezone' => ini_get('date.timezone'),
            'default_charset' => ini_get('default_charset'),
            'opcache.enable' => ini_get('opcache.enable'),
            'opcache.memory_consumption' => ini_get('opcache.memory_consumption'),
            'session.gc_maxlifetime' => ini_get('session.gc_maxlifetime'),
            'session.save_handler' => ini_get('session.save_handler')
        ];
        
        $data = [
            'title' => '⚙️ PHP Конфигурация',
            'status' => $hasErrors ? '❌ Error' : '✅ OK',
            'checks' => $checks,
            'additional' => $additionalSettings
        ];
        
        if ($hasErrors) {
            $data['error'] = 'Некоторые настройки PHP не соответствуют требованиям';
            $this->failedChecks++;
        } else {
            $this->passedChecks++;
        }
        
        $this->diagnostics['php_config'] = $data;
    }

    private function checkPHPExtensions(): void
    {
        $this->totalChecks++;
        
        $requiredExtensions = [
            'pdo' => 'База данных',
            'pdo_mysql' => 'MySQL драйвер',
            'json' => 'JSON обработка',
            'curl' => 'HTTP запросы',
            'mbstring' => 'Мультибайтовые строки',
            'openssl' => 'Шифрование',
            'session' => 'Сессии',
            'zip' => 'Архивы',
            'gd' => 'Обработка изображений',
            'fileinfo' => 'Определение типов файлов',
            'bcmath' => 'Точные вычисления',
            'intl' => 'Интернационализация'
        ];
        
        $optionalExtensions = [
            'opcache' => 'Кеширование кода',
            'redis' => 'Redis поддержка',
            'imagick' => 'Расширенная обработка изображений',
            'apcu' => 'Пользовательский кеш',
            'xdebug' => 'Отладка',
            'igbinary' => 'Бинарная сериализация'
        ];
        
        $installedRequired = [];
        $missingRequired = [];
        $installedOptional = [];
        
        foreach ($requiredExtensions as $ext => $desc) {
            if (extension_loaded($ext)) {
                $installedRequired[$ext] = $desc;
            } else {
                $missingRequired[$ext] = $desc;
            }
        }
        
        foreach ($optionalExtensions as $ext => $desc) {
            if (extension_loaded($ext)) {
                $installedOptional[$ext] = $desc;
            }
        }
        
        $data = [
            'title' => '🧩 PHP Расширения',
            'status' => empty($missingRequired) ? '✅ OK' : '❌ Error',
            'required' => [
                'installed' => $installedRequired,
                'missing' => $missingRequired
            ],
            'optional' => $installedOptional,
            'total_loaded' => count(get_loaded_extensions())
        ];
        
        if (!empty($missingRequired)) {
            $data['error'] = 'Отсутствуют обязательные расширения: ' . implode(', ', array_keys($missingRequired));
            $this->failedChecks++;
            $this->criticalErrors[] = 'Отсутствуют PHP расширения';
        } else {
            $this->passedChecks++;
        }
        
        $this->diagnostics['php_extensions'] = $data;
    }

    private function checkFileSystem(): void
    {
        $this->totalChecks++;
        
        $paths = [
            'root' => Paths::get('root'),
            'public' => Paths::get('public'),
            'config' => Paths::get('config'),
            'logs' => Paths::get('logs'),
            'cache' => Paths::get('cache'),
            'sessions' => Paths::get('sessions'),
            'uploads' => Paths::get('uploads'),
            'assets' => Paths::get('assets')
        ];
        
        $results = [];
        $hasErrors = false;
        
        foreach ($paths as $name => $path) {
            $exists = file_exists($path);
            $readable = $exists && is_readable($path);
            $writable = $exists && is_writable($path);
            
            $results[$name] = [
                'path' => $path,
                'exists' => $exists ? '✅' : '❌',
                'readable' => $readable ? '✅' : '❌',
                'writable' => $writable ? '✅' : '❌'
            ];
            
            if (!$exists || !$readable) {
                $hasErrors = true;
            }
            
            // Некоторые директории должны быть записываемыми
            if (in_array($name, ['logs', 'cache', 'sessions', 'uploads']) && !$writable) {
                $hasErrors = true;
            }
        }
        
        $data = [
            'title' => '📁 Файловая система',
            'status' => $hasErrors ? '❌ Error' : '✅ OK',
            'paths' => $results
        ];
        
        if ($hasErrors) {
            $data['error'] = 'Проблемы с правами доступа к директориям';
            $this->failedChecks++;
        } else {
            $this->passedChecks++;
        }
        
        $this->diagnostics['filesystem'] = $data;
    }

    private function checkPermissions(): void
    {
        $this->totalChecks++;
        
        $criticalFiles = [
            '/etc/vdestor/config/.env' => '0600',
            '/etc/vdestor/config/database.ini' => '0600',
            '/etc/vdestor/config/app.ini' => '0600'
        ];
        
        $results = [];
        $hasErrors = false;
        
        foreach ($criticalFiles as $file => $expectedPerms) {
            if (file_exists($file)) {
                $actualPerms = substr(sprintf('%o', fileperms($file)), -4);
                $owner = posix_getpwuid(fileowner($file))['name'] ?? 'unknown';
                $group = posix_getgrgid(filegroup($file))['name'] ?? 'unknown';
                
                $results[$file] = [
                    'exists' => '✅',
                    'perms' => $actualPerms,
                    'expected' => $expectedPerms,
                    'secure' => $actualPerms === $expectedPerms ? '✅' : '❌',
                    'owner' => $owner,
                    'group' => $group
                ];
                
                if ($actualPerms !== $expectedPerms) {
                    $hasErrors = true;
                }
            } else {
                $results[$file] = [
                    'exists' => '❌',
                    'perms' => 'N/A',
                    'expected' => $expectedPerms,
                    'secure' => '❌'
                ];
                $hasErrors = true;
            }
        }
        
        $data = [
            'title' => '🔐 Права доступа',
            'status' => $hasErrors ? '⚠️ Warning' : '✅ OK',
            'files' => $results
        ];
        
        if ($hasErrors) {
            $data['warning'] = 'Неправильные права доступа к критическим файлам';
            $this->warningChecks++;
        } else {
            $this->passedChecks++;
        }
        
        $this->diagnostics['permissions'] = $data;
    }

    private function checkDiskSpace(): void
    {
        $this->totalChecks++;
        
        $partitions = [];
        
        // Основные разделы
        $paths = [
            '/' => 'Корневой раздел',
            Paths::get('root') => 'Директория приложения',
            '/tmp' => 'Временные файлы',
            Paths::get('logs') => 'Логи'
        ];
        
        foreach ($paths as $path => $name) {
            if (is_dir($path)) {
                $free = disk_free_space($path);
                $total = disk_total_space($path);
                $used = $total - $free;
                $percent = round(($used / $total) * 100, 2);
                
                $partitions[$name] = [
                    'path' => $path,
                    'total' => $this->formatBytes($total),
                    'used' => $this->formatBytes($used),
                    'free' => $this->formatBytes($free),
                    'percent_used' => $percent,
                    'status' => $percent > 90 ? '❌' : ($percent > 80 ? '⚠️' : '✅')
                ];
            }
        }
        
        $criticalSpace = false;
        $warningSpace = false;
        
        foreach ($partitions as $partition) {
            if ($partition['percent_used'] > 90) {
                $criticalSpace = true;
            } elseif ($partition['percent_used'] > 80) {
                $warningSpace = true;
            }
        }
        
        $data = [
            'title' => '💾 Дисковое пространство',
            'status' => $criticalSpace ? '❌ Critical' : ($warningSpace ? '⚠️ Warning' : '✅ OK'),
            'partitions' => $partitions
        ];
        
        if ($criticalSpace) {
            $data['error'] = 'Критически мало свободного места на диске';
            $this->failedChecks++;
            $this->criticalErrors[] = 'Мало места на диске';
        } elseif ($warningSpace) {
            $data['warning'] = 'Заканчивается свободное место на диске';
            $this->warningChecks++;
        } else {
            $this->passedChecks++;
        }
        
        $this->diagnostics['disk_space'] = $data;
    }

    private function checkSystemLoad(): void
    {
        $this->totalChecks++;
        
        $loadAvg = sys_getloadavg();
        $cpuCount = $this->getCPUCount();
        
        $data = [
            'title' => '📊 Нагрузка системы',
            'load_average' => [
                '1_min' => round($loadAvg[0], 2),
                '5_min' => round($loadAvg[1], 2),
                '15_min' => round($loadAvg[2], 2)
            ],
            'cpu_cores' => $cpuCount,
            'normalized_load' => [
                '1_min' => round($loadAvg[0] / $cpuCount, 2),
                '5_min' => round($loadAvg[1] / $cpuCount, 2),
                '15_min' => round($loadAvg[2] / $cpuCount, 2)
            ]
        ];
        
        // Проверка нагрузки
        $normalizedLoad = $loadAvg[0] / $cpuCount;
        
        if ($normalizedLoad > 1.5) {
            $data['status'] = '❌ Critical';
            $data['error'] = 'Очень высокая нагрузка на систему';
            $this->failedChecks++;
        } elseif ($normalizedLoad > 1.0) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Высокая нагрузка на систему';
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        // Дополнительная информация о процессах
        $data['process_info'] = $this->getProcessInfo();
        
        $this->diagnostics['system_load'] = $data;
    }

    // === 2. СЕТЕВЫЕ ПРОВЕРКИ ===

    private function checkNetworkConnectivity(): void
    {
        $this->totalChecks++;
        
        $hosts = [
            'google.com' => 'Google',
            'yandex.ru' => 'Яндекс',
            'cdnjs.cloudflare.com' => 'CDN',
            'fonts.googleapis.com' => 'Google Fonts'
        ];
        
        $results = [];
        $hasErrors = false;
        
        foreach ($hosts as $host => $name) {
            $start = microtime(true);
            $result = @fsockopen($host, 443, $errno, $errstr, 2);
            $latency = round((microtime(true) - $start) * 1000, 2);
            
            if ($result) {
                fclose($result);
                $results[$name] = [
                    'host' => $host,
                    'status' => '✅',
                    'latency' => $latency . ' ms'
                ];
            } else {
                $results[$name] = [
                    'host' => $host,
                    'status' => '❌',
                    'error' => $errstr
                ];
                $hasErrors = true;
            }
        }
        
        $data = [
            'title' => '🌐 Сетевое подключение',
            'status' => $hasErrors ? '⚠️ Warning' : '✅ OK',
            'hosts' => $results
        ];
        
        if ($hasErrors) {
            $data['warning'] = 'Некоторые внешние сервисы недоступны';
            $this->warningChecks++;
        } else {
            $this->passedChecks++;
        }
        
        $this->diagnostics['network'] = $data;
    }

    private function checkDNS(): void
    {
        $this->totalChecks++;
        
        $domain = 'vdestor.ru';
        $start = microtime(true);
        $records = dns_get_record($domain, DNS_A + DNS_AAAA + DNS_MX);
        $latency = round((microtime(true) - $start) * 1000, 2);
        
        $data = [
            'title' => '🌍 DNS проверка',
            'domain' => $domain,
            'resolution_time' => $latency . ' ms',
            'records' => []
        ];
        
        foreach ($records as $record) {
            $data['records'][] = [
                'type' => $record['type'],
                'value' => $record['ip'] ?? $record['ipv6'] ?? $record['target'] ?? 'N/A',
                'ttl' => $record['ttl']
            ];
        }
        
        if (empty($records)) {
            $data['status'] = '❌ Error';
            $data['error'] = 'DNS записи не найдены';
            $this->failedChecks++;
        } elseif ($latency > 500) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Медленное разрешение DNS';
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['dns'] = $data;
    }

    private function checkHTTPS(): void
    {
        $this->totalChecks++;
        
        $url = 'https://vdestor.ru';
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => true,
                'verify_peer_name' => true
            ]
        ]);
        
        $stream = @stream_socket_client(
            'ssl://vdestor.ru:443',
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $context
        );
        
        $data = [
            'title' => '🔒 HTTPS сертификат',
            'url' => $url
        ];
        
        if ($stream) {
            $params = stream_context_get_params($stream);
            $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
            
            $validFrom = date('Y-m-d', $cert['validFrom_time_t']);
            $validTo = date('Y-m-d', $cert['validTo_time_t']);
            $daysLeft = floor(($cert['validTo_time_t'] - time()) / 86400);
            
            $data['certificate'] = [
                'issuer' => $cert['issuer']['O'] ?? 'Unknown',
                'subject' => $cert['subject']['CN'] ?? 'Unknown',
                'valid_from' => $validFrom,
                'valid_to' => $validTo,
                'days_left' => $daysLeft
            ];
            
            if ($daysLeft < 7) {
                $data['status'] = '❌ Critical';
                $data['error'] = 'Сертификат скоро истечет!';
                $this->failedChecks++;
                $this->criticalErrors[] = 'SSL сертификат истекает';
            } elseif ($daysLeft < 30) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Сертификат истекает менее чем через 30 дней';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
            fclose($stream);
        } else {
            $data['status'] = '❌ Error';
            $data['error'] = 'Не удалось проверить SSL сертификат: ' . $errstr;
            $this->failedChecks++;
        }
        
        $this->diagnostics['https'] = $data;
    }

    // === 3. БАЗА ДАННЫХ ===

    private function checkDatabase(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Версия MySQL
            $version = $pdo->query("SELECT VERSION()")->fetchColumn();
            
            // Статус соединения
            $status = $pdo->query("SHOW STATUS LIKE 'Threads_connected'")->fetch();
            $connections = $status['Value'] ?? 0;
            
            // Переменные
            $variables = [];
            $stmt = $pdo->query("SHOW VARIABLES LIKE '%max_connections%'");
            while ($row = $stmt->fetch()) {
                $variables[$row['Variable_name']] = $row['Value'];
            }
            
            $data = [
                'title' => '🗄️ База данных MySQL',
                'status' => '✅ OK',
                'info' => [
                    'version' => $version,
                    'active_connections' => $connections,
                    'max_connections' => $variables['max_connections'] ?? 'N/A',
                    'connection_usage' => round(($connections / ($variables['max_connections'] ?? 1)) * 100, 2) . '%'
                ]
            ];
            
            // Проверка версии
            if (version_compare($version, '5.7.0', '<')) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Рекомендуется обновить MySQL до версии 5.7 или выше';
                $this->warningChecks++;
            } else {
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '🗄️ База данных MySQL',
                'status' => '❌ Error',
                'error' => 'Не удалось подключиться к БД: ' . $e->getMessage()
            ];
            $this->failedChecks++;
            $this->criticalErrors[] = 'БД недоступна';
        }
        
        $this->diagnostics['database'] = $data;
    }

    private function checkDatabaseTables(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Необходимые таблицы
            $requiredTables = [
                'users', 'roles', 'products', 'brands', 'series', 'categories',
                'prices', 'stock_balances', 'warehouses', 'cities', 'carts',
                'specifications', 'sessions', 'audit_logs', 'metrics'
            ];
            
            // Получаем список таблиц
            $stmt = $pdo->query("SHOW TABLES");
            $existingTables = $stmt->fetchAll(\PDO::FETCH_COLUMN);
            
            $missingTables = array_diff($requiredTables, $existingTables);
            
            // Статистика по таблицам
            $tableStats = [];
            $totalRows = 0;
            $totalSize = 0;
            
            $stmt = $pdo->query("
                SELECT 
                    TABLE_NAME,
                    TABLE_ROWS,
                    DATA_LENGTH + INDEX_LENGTH as size,
                    ENGINE
                FROM information_schema.TABLES 
                WHERE TABLE_SCHEMA = DATABASE()
                ORDER BY DATA_LENGTH + INDEX_LENGTH DESC
                LIMIT 20
            ");
            
            while ($row = $stmt->fetch()) {
                $tableStats[] = [
                    'name' => $row['TABLE_NAME'],
                    'rows' => (int)$row['TABLE_ROWS'],
                    'size' => $this->formatBytes($row['size']),
                    'engine' => $row['ENGINE']
                ];
                $totalRows += $row['TABLE_ROWS'];
                $totalSize += $row['size'];
            }
            
            $data = [
                'title' => '📋 Таблицы базы данных',
                'total_tables' => count($existingTables),
                'total_rows' => $totalRows,
                'total_size' => $this->formatBytes($totalSize),
                'top_tables' => $tableStats
            ];
            
            if (!empty($missingTables)) {
                $data['status'] = '❌ Error';
                $data['error'] = 'Отсутствуют таблицы: ' . implode(', ', $missingTables);
                $data['missing_tables'] = $missingTables;
                $this->failedChecks++;
                $this->criticalErrors[] = 'Отсутствуют таблицы БД';
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '📋 Таблицы базы данных',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['database_tables'] = $data;
    }

    private function checkDatabaseIndexes(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Проверяем отсутствующие индексы на больших таблицах
            $missingIndexes = [];
            
            // Проверка индексов products
            $stmt = $pdo->query("SHOW INDEX FROM products");
            $productIndexes = [];
            while ($row = $stmt->fetch()) {
                $productIndexes[] = $row['Column_name'];
            }
            
            $requiredProductIndexes = ['external_id', 'sku', 'brand_id', 'series_id'];
            $missing = array_diff($requiredProductIndexes, $productIndexes);
            if (!empty($missing)) {
                $missingIndexes['products'] = $missing;
            }
            
            // Проверка индексов prices
            $stmt = $pdo->query("SHOW INDEX FROM prices");
            $priceIndexes = [];
            while ($row = $stmt->fetch()) {
                $priceIndexes[] = $row['Column_name'];
            }
            
            $requiredPriceIndexes = ['product_id', 'valid_from'];
            $missing = array_diff($requiredPriceIndexes, $priceIndexes);
            if (!empty($missing)) {
                $missingIndexes['prices'] = $missing;
            }
            
            $data = [
                'title' => '🔍 Индексы базы данных',
                'missing_indexes' => $missingIndexes
            ];
            
            if (!empty($missingIndexes)) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Отсутствуют некоторые индексы для оптимальной производительности';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $data['info'] = 'Все необходимые индексы присутствуют';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '🔍 Индексы базы данных',
                'status' = '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['database_indexes'] = $data;
    }

    private function checkDatabasePerformance(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Тестовые запросы
            $queries = [
                'simple_select' => "SELECT 1",
                'count_products' => "SELECT COUNT(*) FROM products",
                'join_query' => "SELECT COUNT(*) FROM products p JOIN brands b ON p.brand_id = b.brand_id",
                'search_query' => "SELECT * FROM products WHERE name LIKE '%test%' LIMIT 10"
            ];
            
            $results = [];
            $slowQueries = [];
            
            foreach ($queries as $name => $sql) {
                $start = microtime(true);
                try {
                    $stmt = $pdo->query($sql);
                    $stmt->fetchAll();
                    $duration = round((microtime(true) - $start) * 1000, 2);
                    
                    $results[$name] = $duration . ' ms';
                    
                    if ($duration > 100) {
                        $slowQueries[] = $name;
                    }
                } catch (\Exception $e) {
                    $results[$name] = 'Error: ' . $e->getMessage();
                }
            }
            
            $data = [
                'title' => '⚡ Производительность БД',
                'query_times' => $results
            ];
            
            if (!empty($slowQueries)) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Медленные запросы: ' . implode(', ', $slowQueries);
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '⚡ Производительность БД',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['database_performance'] = $data;
    }

    private function checkDatabaseIntegrity(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            $issues = [];
            
            // Проверка товаров без цен
            $stmt = $pdo->query("
                SELECT COUNT(*) FROM products p
                LEFT JOIN prices pr ON p.product_id = pr.product_id AND pr.is_base = 1
                WHERE pr.price_id IS NULL
            ");
            $productsWithoutPrices = (int)$stmt->fetchColumn();
            
            if ($productsWithoutPrices > 0) {
                $issues[] = "Товары без цен: $productsWithoutPrices";
            }
            
            // Проверка товаров без остатков
            $stmt = $pdo->query("
                SELECT COUNT(DISTINCT p.product_id) FROM products p
                LEFT JOIN stock_balances sb ON p.product_id = sb.product_id
                WHERE sb.product_id IS NULL
            ");
            $productsWithoutStock = (int)$stmt->fetchColumn();
            
            if ($productsWithoutStock > 0) {
                $issues[] = "Товары без остатков: $productsWithoutStock";
            }
            
            // Проверка дубликатов артикулов
            $stmt = $pdo->query("
                SELECT external_id, COUNT(*) as cnt 
                FROM products 
                GROUP BY external_id 
                HAVING cnt > 1
            ");
            $duplicates = $stmt->fetchAll();
            
            if (!empty($duplicates)) {
                $issues[] = "Дубликаты артикулов: " . count($duplicates);
            }
            
            $data = [
                'title' => '🔧 Целостность данных',
                'issues' => $issues
            ];
            
            if (!empty($issues)) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Обнаружены проблемы с целостностью данных';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $data['info'] = 'Целостность данных в норме';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '🔧 Целостность данных',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['database_integrity'] = $data;
    }

    private function checkDatabaseSize(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Общий размер БД
            $stmt = $pdo->query("
                SELECT 
                    SUM(data_length + index_length) as total_size,
                    SUM(data_length) as data_size,
                    SUM(index_length) as index_size,
                    COUNT(*) as table_count
                FROM information_schema.tables 
                WHERE table_schema = DATABASE()
            ");
            
            $dbStats = $stmt->fetch();
            
            $data = [
                'title' => '💿 Размер базы данных',
                'total_size' => $this->formatBytes($dbStats['total_size']),
                'data_size' => $this->formatBytes($dbStats['data_size']),
                'index_size' => $this->formatBytes($dbStats['index_size']),
                'table_count' => $dbStats['table_count']
            ];
            
            // Проверка размера
            $sizeGB = $dbStats['total_size'] / (1024 * 1024 * 1024);
            
            if ($sizeGB > 10) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'База данных очень большая, рекомендуется оптимизация';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '💿 Размер базы данных',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['database_size'] = $data;
    }

    // === 4. OPENSEARCH ===

    private function checkOpenSearch(): void
    {
        $this->totalChecks++;
        
        try {
            $client = ClientBuilder::create()
                ->setHosts(['localhost:9200'])
                ->setConnectionParams(['timeout' => 5])
                ->build();
            
            // Проверка здоровья кластера
            $health = $client->cluster()->health();
            
            $data = [
                'title' => '🔎 OpenSearch',
                'cluster_name' => $health['cluster_name'],
                'status' => $health['status'],
                'nodes' => $health['number_of_nodes'],
                'data_nodes' => $health['number_of_data_nodes'],
                'active_shards' => $health['active_shards'],
                'relocating_shards' => $health['relocating_shards'],
                'unassigned_shards' => $health['unassigned_shards']
            ];
            
            if ($health['status'] === 'red') {
                $data['status'] = '❌ Critical';
                $data['error'] = 'Кластер OpenSearch в критическом состоянии';
                $this->failedChecks++;
                $this->criticalErrors[] = 'OpenSearch недоступен';
            } elseif ($health['status'] === 'yellow') {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Кластер OpenSearch требует внимания';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '🔎 OpenSearch',
                'status' => '❌ Error',
                'error' => 'OpenSearch недоступен: ' . $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['opensearch'] = $data;
    }

    private function checkOpenSearchIndexes(): void
    {
        $this->totalChecks++;
        
        try {
            $client = ClientBuilder::create()
                ->setHosts(['localhost:9200'])
                ->setConnectionParams(['timeout' => 5])
                ->build();
            
            // Проверка индексов
            $indices = $client->indices()->stats(['index' => 'products*']);
            
            $indexList = [];
            $totalDocs = 0;
            $totalSize = 0;
            
            foreach ($indices['indices'] as $indexName => $indexData) {
                $docs = $indexData['primaries']['docs']['count'] ?? 0;
                $size = $indexData['primaries']['store']['size_in_bytes'] ?? 0;
                
                $indexList[] = [
                    'name' => $indexName,
                    'docs' => $docs,
                    'size' => $this->formatBytes($size),
                    'health' => $indexData['health'] ?? 'unknown'
                ];
                
                $totalDocs += $docs;
                $totalSize += $size;
            }
            
            // Проверка алиаса
            $aliasExists = false;
            try {
                $aliases = $client->indices()->getAlias(['name' => 'products_current']);
                $aliasExists = !empty($aliases);
            } catch (\Exception $e) {
                // Алиас не существует
            }
            
            $data = [
                'title' => '📑 Индексы OpenSearch',
                'total_indices' => count($indexList),
                'total_documents' => $totalDocs,
                'total_size' => $this->formatBytes($totalSize),
                'indices' => $indexList,
                'alias_exists' => $aliasExists
            ];
            
            if (!$aliasExists) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Алиас products_current не настроен';
                $this->warningChecks++;
            } elseif ($totalDocs === 0) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Индексы пустые, нет документов';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '📑 Индексы OpenSearch',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['opensearch_indexes'] = $data;
    }

    private function checkOpenSearchPerformance(): void
    {
        $this->totalChecks++;
        
        try {
            $client = ClientBuilder::create()
                ->setHosts(['localhost:9200'])
                ->setConnectionParams(['timeout' => 5])
                ->build();
            
            // Тестовые запросы
            $queries = [
                'match_all' => [
                    'query' => ['match_all' => new \stdClass()],
                    'size' => 1
                ],
                'term_search' => [
                    'query' => ['term' => ['external_id' => 'TEST123']],
                    'size' => 1
                ],
                'fuzzy_search' => [
                    'query' => ['match' => ['name' => 'автомат']],
                    'size' => 10
                ]
            ];
            
            $results = [];
            
            foreach ($queries as $name => $body) {
                $start = microtime(true);
                try {
                    $response = $client->search([
                        'index' => 'products_current',
                        'body' => $body
                    ]);
                    $duration = round((microtime(true) - $start) * 1000, 2);
                    
                    $results[$name] = [
                        'time' => $duration . ' ms',
                        'hits' => $response['hits']['total']['value'] ?? 0
                    ];
                } catch (\Exception $e) {
                    $results[$name] = ['error' => $e->getMessage()];
                }
            }
            
            $data = [
                'title' => '⚡ Производительность OpenSearch',
                'query_results' => $results
            ];
            
            // Проверка производительности
            $slowQueries = 0;
            foreach ($results as $result) {
                if (isset($result['time'])) {
                    $time = (float)str_replace(' ms', '', $result['time']);
                    if ($time > 100) {
                        $slowQueries++;
                    }
                }
            }
            
            if ($slowQueries > 0) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = "Медленные запросы: $slowQueries";
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '⚡ Производительность OpenSearch',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['opensearch_performance'] = $data;
    }

    // === 5. КЕШ ===

    private function checkCache(): void
    {
        $this->totalChecks++;
        
        try {
            // Тест записи
            $testKey = 'diagnostic_test_' . time();
            $testValue = ['test' => true, 'time' => time()];
            
            $writeResult = Cache::set($testKey, $testValue, 60);
            
            // Тест чтения
            $readValue = Cache::get($testKey);
            
            // Тест удаления
            $deleteResult = Cache::delete($testKey);
            
            // Получаем статистику
            $stats = Cache::getStats();
            
            $data = [
                'title' => '💾 Система кеширования',
                'enabled' => $stats['enabled'] ?? false,
                'cache_dir' => $stats['cache_dir'] ?? 'N/A',
                'total_files' => $stats['total_files'] ?? 0,
                'valid_files' => $stats['valid_files'] ?? 0,
                'total_size' => $this->formatBytes($stats['total_size'] ?? 0),
                'tests' => [
                    'write' => $writeResult ? '✅' : '❌',
                    'read' => ($readValue === $testValue) ? '✅' : '❌',
                    'delete' => $deleteResult ? '✅' : '❌'
                ]
            ];
            
            if (!$writeResult || $readValue !== $testValue) {
                $data['status'] = '❌ Error';
                $data['error'] = 'Кеш не работает корректно';
                $this->failedChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '💾 Система кеширования',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['cache'] = $data;
    }

    private function checkCachePerformance(): void
    {
        $this->totalChecks++;
        
        try {
            $iterations = 1000;
            $testData = str_repeat('x', 1024); // 1KB данных
            
            // Тест записи
            $writeStart = microtime(true);
            for ($i = 0; $i < $iterations; $i++) {
                Cache::set("perf_test_$i", $testData, 60);
            }
            $writeTime = round((microtime(true) - $writeStart) * 1000, 2);
            
            // Тест чтения
            $readStart = microtime(true);
            for ($i = 0; $i < $iterations; $i++) {
                Cache::get("perf_test_$i");
            }
            $readTime = round((microtime(true) - $readStart) * 1000, 2);
            
            // Очистка
            for ($i = 0; $i < $iterations; $i++) {
                Cache::delete("perf_test_$i");
            }
            
            $data = [
                'title' => '⚡ Производительность кеша',
                'iterations' => $iterations,
                'write_time' => $writeTime . ' ms',
                'read_time' => $readTime . ' ms',
                'avg_write' => round($writeTime / $iterations, 3) . ' ms',
                'avg_read' => round($readTime / $iterations, 3) . ' ms'
            ];
            
            if ($writeTime > 1000 || $readTime > 500) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Медленная работа кеша';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '⚡ Производительность кеша',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['cache_performance'] = $data;
    }

    private function checkCacheSize(): void
    {
        $this->totalChecks++;
        
        try {
            $stats = Cache::getStats();
            $cacheDir = $stats['cache_dir'] ?? '/tmp/vdestor_cache';
            
            $totalSize = 0;
            $fileCount = 0;
            $oldestFile = time();
            
            if (is_dir($cacheDir)) {
                $files = glob($cacheDir . '/*.cache');
                $fileCount = count($files);
                
                foreach ($files as $file) {
                    $totalSize += filesize($file);
                    $mtime = filemtime($file);
                    if ($mtime < $oldestFile) {
                        $oldestFile = $mtime;
                    }
                }
            }
            
            $data = [
                'title' => '📊 Размер кеша',
                'cache_dir' => $cacheDir,
                'total_files' => $fileCount,
                'total_size' => $this->formatBytes($totalSize),
                'oldest_file_age' => $this->formatAge(time() - $oldestFile)
            ];
            
            if ($totalSize > 1024 * 1024 * 1024) { // 1GB
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Кеш занимает много места';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '📊 Размер кеша',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['cache_size'] = $data;
    }

    // === 6. СЕССИИ ===

    private function checkSessions(): void
    {
        $this->totalChecks++;
        
        try {
            $sessionHandler = ini_get('session.save_handler');
            $sessionPath = ini_get('session.save_path');
            $sessionLifetime = ini_get('session.gc_maxlifetime');
            
            $data = [
                'title' => '🔐 Система сессий',
                'handler' => $sessionHandler,
                'save_path' => $sessionPath,
                'lifetime' => $sessionLifetime . ' секунд',
                'session_id' => session_id(),
                'session_name' => session_name()
            ];
            
            // Проверка работы сессий
            $testKey = 'diagnostic_test_' . time();
            $_SESSION[$testKey] = 'test_value';
            
            if ($_SESSION[$testKey] === 'test_value') {
                unset($_SESSION[$testKey]);
                $data['status'] = '✅ OK';
                $data['session_working'] = true;
                $this->passedChecks++;
            } else {
                $data['status'] = '❌ Error';
                $data['error'] = 'Сессии не работают';
                $data['session_working'] = false;
                $this->failedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '🔐 Система сессий',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['sessions'] = $data;
    }

    private function checkSessionSecurity(): void
    {
        $this->totalChecks++;
        
        $settings = [
            'session.cookie_secure' => ini_get('session.cookie_secure'),
            'session.cookie_httponly' => ini_get('session.cookie_httponly'),
            'session.cookie_samesite' => ini_get('session.cookie_samesite'),
            'session.use_strict_mode' => ini_get('session.use_strict_mode'),
            'session.use_only_cookies' => ini_get('session.use_only_cookies')
        ];
        
        $issues = [];
        
        if (!$settings['session.cookie_secure'] && !empty($_SERVER['HTTPS'])) {
            $issues[] = 'session.cookie_secure должен быть включен для HTTPS';
        }
        
        if (!$settings['session.cookie_httponly']) {
            $issues[] = 'session.cookie_httponly должен быть включен';
        }
        
        if (!$settings['session.cookie_samesite']) {
            $issues[] = 'session.cookie_samesite должен быть установлен';
        }
        
        $data = [
            'title' => '🛡️ Безопасность сессий',
            'settings' => $settings,
            'issues' => $issues
        ];
        
        if (!empty($issues)) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Настройки безопасности сессий требуют внимания';
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['session_security'] = $data;
    }

    private function checkActiveSessions(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Подсчет активных сессий
            $stmt = $pdo->query("
                SELECT 
                    COUNT(*) as total,
                    COUNT(DISTINCT user_id) as unique_users,
                    COUNT(CASE WHEN user_id IS NULL THEN 1 END) as guest_sessions
                FROM sessions 
                WHERE expires_at > NOW()
            ");
            
            $sessionStats = $stmt->fetch();
            
            // Старые сессии
            $stmt = $pdo->query("
                SELECT COUNT(*) FROM sessions 
                WHERE expires_at < NOW()
            ");
            $expiredSessions = (int)$stmt->fetchColumn();
            
            $data = [
                'title' => '👥 Активные сессии',
                'active_sessions' => $sessionStats['total'],
                'unique_users' => $sessionStats['unique_users'],
                'guest_sessions' => $sessionStats['guest_sessions'],
                'expired_sessions' => $expiredSessions
            ];
            
            if ($expiredSessions > 1000) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Много устаревших сессий, требуется очистка';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '👥 Активные сессии',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['active_sessions'] = $data;
    }

    // === 7. ОЧЕРЕДИ ===

    private function checkQueues(): void
    {
        $this->totalChecks++;
        
        try {
            $stats = QueueService::getStats();
            
            $data = [
                'title' => '📋 Очереди задач',
                'queue_length' => $stats['queue_length'] ?? 0,
                'by_status' => $stats['by_status'] ?? [],
                'by_type' => $stats['by_type'] ?? []
            ];
            
            $pending = $stats['by_status']['pending']['count'] ?? 0;
            $failed = $stats['by_status']['failed']['count'] ?? 0;
            
            if ($failed > 100) {
                $data['status'] = '❌ Error';
                $data['error'] = "Много неудачных задач: $failed";
                $this->failedChecks++;
            } elseif ($pending > 1000) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = "Большая очередь задач: $pending";
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '📋 Очереди задач',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['queues'] = $data;
    }

    private function checkQueueWorkers(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Проверка последней активности воркеров
            $stmt = $pdo->query("
                SELECT 
                    type,
                    MAX(started_at) as last_run,
                    COUNT(CASE WHEN status = 'processing' THEN 1 END) as processing
                FROM job_queue
                GROUP BY type
            ");
            
            $workerStatus = [];
            while ($row = $stmt->fetch()) {
                $lastRun = $row['last_run'] ? strtotime($row['last_run']) : 0;
                $minutesAgo = $lastRun ? round((time() - $lastRun) / 60) : null;
                
                $workerStatus[$row['type']] = [
                    'last_run' => $row['last_run'],
                    'minutes_ago' => $minutesAgo,
                    'processing' => $row['processing']
                ];
            }
            
            $data = [
                'title' => '⚙️ Воркеры очередей',
                'workers' => $workerStatus
            ];
            
            $inactiveWorkers = 0;
            foreach ($workerStatus as $type => $status) {
                if ($status['minutes_ago'] > 60) {
                    $inactiveWorkers++;
                }
            }
            
            if ($inactiveWorkers > 0) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = "Неактивные воркеры: $inactiveWorkers";
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '⚙️ Воркеры очередей',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['queue_workers'] = $data;
    }

    private function checkFailedJobs(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Последние неудачные задачи
            $stmt = $pdo->query("
                SELECT 
                    type,
                    last_error,
                    attempts,
                    failed_at
                FROM job_queue
                WHERE status = 'failed'
                ORDER BY failed_at DESC
                LIMIT 10
            ");
            
            $failedJobs = $stmt->fetchAll();
            
            // Статистика по типам
            $stmt = $pdo->query("
                SELECT 
                    type,
                    COUNT(*) as count
                FROM job_queue
                WHERE status = 'failed'
                GROUP BY type
            ");
            
            $failedByType = [];
            while ($row = $stmt->fetch()) {
                $failedByType[$row['type']] = $row['count'];
            }
            
            $data = [
                'title' => '❌ Неудачные задачи',
                'total_failed' => array_sum($failedByType),
                'by_type' => $failedByType,
                'recent_failures' => $failedJobs
            ];
            
            if (array_sum($failedByType) > 100) {
                $data['status'] = '❌ Error';
                $data['error'] = 'Слишком много неудачных задач';
                $this->failedChecks++;
            } elseif (array_sum($failedByType) > 50) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Растет количество неудачных задач';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '❌ Неудачные задачи',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['failed_jobs'] = $data;
    }

    // === 8. EMAIL ===

    private function checkEmailConfiguration(): void
    {
        $this->totalChecks++;
        
        $config = [
            'from_email' => Env::get('MAIL_FROM_ADDRESS', 'not_set'),
            'from_name' => Env::get('MAIL_FROM_NAME', 'not_set'),
            'driver' => Env::get('MAIL_DRIVER', 'mail'),
            'host' => Env::get('MAIL_HOST', 'not_set'),
            'port' => Env::get('MAIL_PORT', 'not_set'),
            'encryption' => Env::get('MAIL_ENCRYPTION', 'none')
        ];
        
        $issues = [];
        
        if ($config['from_email'] === 'not_set') {
            $issues[] = 'Email отправителя не настроен';
        }
        
        if ($config['driver'] === 'smtp' && $config['host'] === 'not_set') {
            $issues[] = 'SMTP сервер не настроен';
        }
        
        $data = [
            'title' => '📧 Настройки Email',
            'config' => $config,
            'issues' => $issues
        ];
        
        if (!empty($issues)) {
            $data['status'] = '❌ Error';
            $data['error'] = 'Проблемы с настройкой email';
            $this->failedChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['email_config'] = $data;
    }

    private function checkEmailDelivery(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Статистика отправки за последние 7 дней
            $stmt = $pdo->query("
                SELECT 
                    COUNT(*) as total_sent,
                    COUNT(opened_at) as opened,
                    COUNT(clicked_at) as clicked,
                    MIN(sent_at) as first_sent,
                    MAX(sent_at) as last_sent
                FROM email_logs
                WHERE sent_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ");
            
            $emailStats = $stmt->fetch();
            
            $data = [
                'title' => '📮 Доставка Email',
                'last_7_days' => [
                    'sent' => $emailStats['total_sent'],
                    'opened' => $emailStats['opened'],
                    'clicked' => $emailStats['clicked'],
                    'open_rate' => $emailStats['total_sent'] > 0 
                        ? round(($emailStats['opened'] / $emailStats['total_sent']) * 100, 2) . '%'
                        : '0%'
                ],
                'last_sent' => $emailStats['last_sent']
            ];
            
            if ($emailStats['total_sent'] === 0) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Нет отправленных писем за последние 7 дней';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '📮 Доставка Email',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['email_delivery'] = $data;
    }

    // === 9. БЕЗОПАСНОСТЬ ===

    private function checkSecurityHeaders(): void
    {
        $this->totalChecks++;
        
        $headers = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Strict-Transport-Security' => null // Проверяется только для HTTPS
        ];
        
        $issues = [];
        $presentHeaders = [];
        
        foreach ($headers as $header => $expectedValue) {
            $value = $_SERVER['HTTP_' . str_replace('-', '_', strtoupper($header))] ?? null;
            
            if ($header === 'Strict-Transport-Security' && empty($_SERVER['HTTPS'])) {
                continue; // Пропускаем для HTTP
            }
            
            if ($value === null) {
                $issues[] = "Отсутствует заголовок: $header";
            } elseif ($expectedValue !== null && $value !== $expectedValue) {
                $issues[] = "Неправильное значение $header: $value (ожидается: $expectedValue)";
            } else {
                $presentHeaders[$header] = $value;
            }
        }
        
        $data = [
            'title' => '🛡️ Заголовки безопасности',
            'present_headers' => $presentHeaders,
            'issues' => $issues
        ];
        
        if (!empty($issues)) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Некоторые заголовки безопасности отсутствуют или неправильные';
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['security_headers'] = $data;
    }

    private function checkFileSecurityPermissions(): void
    {
        $this->totalChecks++;
        
        $sensitiveFiles = [
            '/etc/vdestor/config/.env',
            '/etc/vdestor/config/database.ini',
            '/etc/vdestor/config/app.ini',
            Paths::get('root') . '/composer.json',
            Paths::get('root') . '/composer.lock'
        ];
        
        $issues = [];
        
        foreach ($sensitiveFiles as $file) {
            if (file_exists($file)) {
                $perms = fileperms($file);
                
                // Проверка на чтение всеми
                if ($perms & 0004) {
                    $issues[] = "$file доступен для чтения всем";
                }
                
                // Проверка на запись группой или всеми
                if ($perms & 0022) {
                    $issues[] = "$file доступен для записи группой/всеми";
                }
            }
        }
        
        $data = [
            'title' => '🔒 Права доступа к файлам',
            'checked_files' => count($sensitiveFiles),
            'issues' => $issues
        ];
        
        if (!empty($issues)) {
            $data['status'] = '❌ Error';
            $data['error'] = 'Критические проблемы с правами доступа';
            $this->failedChecks++;
            $this->criticalErrors[] = 'Небезопасные права доступа';
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['file_security'] = $data;
    }

    private function checkConfigurationSecurity(): void
    {
        $this->totalChecks++;
        
        $issues = [];
        
        // Проверка debug режима
        if (Env::get('APP_DEBUG', 'false') === 'true') {
            $issues[] = 'Debug режим включен в production';
        }
        
        // Проверка display_errors
        if (ini_get('display_errors') == '1') {
            $issues[] = 'display_errors включен';
        }
        
        // Проверка expose_php
        if (ini_get('expose_php') == '1') {
            $issues[] = 'expose_php включен';
        }
        
        $data = [
            'title' => '⚙️ Безопасность конфигурации',
            'issues' => $issues,
            'environment' => Env::get('APP_ENV', 'unknown')
        ];
        
        if (!empty($issues) && Env::get('APP_ENV') === 'production') {
            $data['status'] = '❌ Error';
            $data['error'] = 'Небезопасные настройки для production';
            $this->failedChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['config_security'] = $data;
    }

    private function checkLoginAttempts(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Заблокированные аккаунты
            $stmt = $pdo->query("
                SELECT COUNT(*) FROM login_attempts 
                WHERE failed_attempts >= 5 
                AND last_attempt > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            ");
            $blockedAccounts = (int)$stmt->fetchColumn();
            
            // Попытки за последний час
            $stmt = $pdo->query("
                SELECT 
                    COUNT(*) as total_attempts,
                    COUNT(DISTINCT identifier) as unique_identifiers,
                    COUNT(DISTINCT ip_address) as unique_ips
                FROM login_attempts
                WHERE last_attempt > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ");
            $recentAttempts = $stmt->fetch();
            
            $data = [
                'title' => '🚫 Попытки входа',
                'blocked_accounts' => $blockedAccounts,
                'last_hour' => [
                    'total_attempts' => $recentAttempts['total_attempts'],
                    'unique_users' => $recentAttempts['unique_identifiers'],
                    'unique_ips' => $recentAttempts['unique_ips']
                ]
            ];
            
            if ($blockedAccounts > 10) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Много заблокированных аккаунтов';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '🚫 Попытки входа',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['login_attempts'] = $data;
    }

    private function checkSuspiciousActivity(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Подозрительные действия за последние 24 часа
            $stmt = $pdo->query("
                SELECT 
                    action,
                    COUNT(*) as count
                FROM audit_logs
                WHERE action IN ('failed_login_attempt', 'permission_denied', 'invalid_token')
                AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY action
            ");
            
            $suspiciousActions = [];
            while ($row = $stmt->fetch()) {
                $suspiciousActions[$row['action']] = $row['count'];
            }
            
            $data = [
                'title' => '🔍 Подозрительная активность',
                'last_24h' => $suspiciousActions,
                'total_suspicious' => array_sum($suspiciousActions)
            ];
            
            if (array_sum($suspiciousActions) > 100) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Высокий уровень подозрительной активности';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            $data = [
                'title' => '🔍 Подозрительная активность',
                'status' => '❌ Error',
                'error' => $e->getMessage()
            ];
            $this->failedChecks++;
        }
        
        $this->diagnostics['suspicious_activity'] = $data;
    }

    // === 10. ПРОИЗВОДИТЕЛЬНОСТЬ ===

    private function checkAPIPerformance(): void
    {
        $this->totalChecks++;
        
        $endpoints = [
            '/api/test' => 'GET',
            '/api/search?q=test' => 'GET',
            '/api/availability?product_ids=1&city_id=1' => 'GET'
        ];
        
        $results = [];
        $slowEndpoints = [];
        
        foreach ($endpoints as $endpoint => $method) {
            $start = microtime(true);
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'https://vdestor.ru' . $endpoint);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            $duration = round((microtime(true) - $start) * 1000, 2);
            
            $results[$endpoint] = [
                'method' => $method,
                'status' => $httpCode,
                'time' => $duration . ' ms'
            ];
            
            if ($duration > 1000) {
                $slowEndpoints[] = $endpoint;
            }
        }
        
        $data = [
            'title' => '⚡ Производительность API',
            'endpoints' => $results
        ];
        
        if (!empty($slowEndpoints)) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Медленные endpoints: ' . implode(', ', $slowEndpoints);
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['api_performance'] = $data;
    }

    private function checkPageLoadTime(): void
    {
        $this->totalChecks++;
        
        $pages = [
            '/' => 'Главная',
            '/shop' => 'Магазин',
            '/cart' => 'Корзина',
            '/login' => 'Вход'
        ];
        
        $results = [];
        $slowPages = [];
        
        foreach ($pages as $path => $name) {
            $start = microtime(true);
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'https://vdestor.ru' . $path);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $size = strlen($response);
            curl_close($ch);
            
            $duration = round((microtime(true) - $start) * 1000, 2);
            
            $results[$name] = [
                'path' => $path,
                'status' => $httpCode,
                'time' => $duration . ' ms',
                'size' => $this->formatBytes($size)
            ];
            
            if ($duration > 2000) {
                $slowPages[] = $name;
            }
        }
        
        $data = [
            'title' => '📄 Скорость загрузки страниц',
            'pages' => $results
        ];
        
        if (!empty($slowPages)) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Медленные страницы: ' . implode(', ', $slowPages);
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['page_load_time'] = $data;
    }

    private function checkSlowQueries(): void
    {
        $this->totalChecks++;
        
        try {
            $pdo = Database::getConnection();
            
            // Получаем медленные запросы из лога
            $stmt = $pdo->query("
                SELECT 
                    query_time,
                    db,
                    sql_text
                FROM mysql.slow_log
                WHERE query_time > 1
                ORDER BY query_time DESC
                LIMIT 10
            ");
            
            $slowQueries = [];
            while ($row = $stmt->fetch()) {
                $slowQueries[] = [
                    'time' => $row['query_time'],
                    'db' => $row['db'],
                    'query' => substr($row['sql_text'], 0, 100) . '...'
                ];
            }
            
            $data = [
                'title' => '🐌 Медленные запросы',
                'slow_queries' => $slowQueries,
                'total' => count($slowQueries)
            ];
            
            if (count($slowQueries) > 5) {
                $data['status'] = '⚠️ Warning';
                $data['warning'] = 'Много медленных запросов';
                $this->warningChecks++;
            } else {
                $data['status'] = '✅ OK';
                $this->passedChecks++;
            }
            
        } catch (\Exception $e) {
            // Если нет доступа к slow_log, пропускаем
            $data = [
                'title' => '🐌 Медленные запросы',
                'status' => '⚠️ Skipped',
                'info' => 'Нет доступа к slow_log'
            ];
            $this->passedChecks++;
        }
        
        $this->diagnostics['slow_queries'] = $data;
    }

    private function checkMemoryUsage(): void
    {
        $this->totalChecks++;
        
        $memoryUsage = memory_get_usage(true);
        $memoryPeak = memory_get_peak_usage(true);
        $memoryLimit = $this->parseSize(ini_get('memory_limit'));
        
        $data = [
            'title' => '💾 Использование памяти',
            'current' => $this->formatBytes($memoryUsage),
            'peak' => $this->formatBytes($memoryPeak),
            'limit' => $this->formatBytes($memoryLimit),
            'usage_percent' => round(($memoryUsage / $memoryLimit) * 100, 2) . '%',
            'peak_percent' => round(($memoryPeak / $memoryLimit) * 100, 2) . '%'
        ];
        
        if (($memoryPeak / $memoryLimit) > 0.8) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Высокое использование памяти';
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['memory_usage'] = $data;
    }

    // === 11. ЛОГИ И ОШИБКИ ===

    private function checkErrorLogs(): void
    {
        $this->totalChecks++;
        
        $logFiles = [
            'PHP' => '/var/log/php/error.log',
            'Nginx' => '/var/log/nginx/error.log',
            'Application' => Paths::get('logs') . '/app.log'
        ];
        
        $results = [];
        $recentErrors = 0;
        
        foreach ($logFiles as $name => $logFile) {
            if (file_exists($logFile)) {
                $size = filesize($logFile);
                $mtime = filemtime($logFile);
                
                // Читаем последние 50 строк
                $lines = $this->tailFile($logFile, 50);
                $errorCount = 0;
                
                foreach ($lines as $line) {
                    if (stripos($line, 'error') !== false || stripos($line, 'fatal') !== false) {
                        $errorCount++;
                    }
                }
                
                $results[$name] = [
                    'file' => $logFile,
                    'size' => $this->formatBytes($size),
                    'last_modified' => date('Y-m-d H:i:s', $mtime),
                    'recent_errors' => $errorCount
                ];
                
                $recentErrors += $errorCount;
            } else {
                $results[$name] = [
                    'file' => $logFile,
                    'status' => 'Файл не найден'
                ];
            }
        }
        
        $data = [
            'title' => '📋 Логи ошибок',
            'logs' => $results,
            'total_recent_errors' => $recentErrors
        ];
        
        if ($recentErrors > 50) {
            $data['status'] = '❌ Error';
            $data['error'] = 'Много недавних ошибок';
            $this->failedChecks++;
        } elseif ($recentErrors > 10) {
            $data['status'] = '⚠️ Warning';
            $data['warning'] = 'Есть недавние ошибки';
            $this->warningChecks++;
        } else {
            $data['status'] = '✅ OK';
            $this->passedChecks++;
        }
        
        $this->diagnostics['error_logs'] = $data;
    }

    private function checkApplicationLogs(): void
    {
        $this->tot
