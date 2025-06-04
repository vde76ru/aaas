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
        $normalizedLoad = $loadAvg[0
