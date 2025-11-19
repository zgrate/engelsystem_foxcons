<?php

declare(strict_types=1);

namespace Engelsystem\Migrations;

use Engelsystem\Database\Migration\Migration;
use Illuminate\Database\Schema\Blueprint;

class AddTelegramToUsersContact extends Migration
{
    public function up(): void
    {
        if (!$this->schema->hasTable('users_contact')) {
            return;
        }

        $this->schema->table('users_contact', function (Blueprint $table): void {
            if (!$this->schema->hasColumn('users_contact', 'telegram')) {
                $table->string('telegram', 64)->nullable()->after('mobile');
            }
        });
    }

    public function down(): void
    {
        if (!$this->schema->hasTable('users_contact')) {
            return;
        }

        $this->schema->table('users_contact', function (Blueprint $table): void {
            if ($this->schema->hasColumn('users_contact', 'telegram')) {
                $table->dropColumn('telegram');
            }
        });
    }
}
