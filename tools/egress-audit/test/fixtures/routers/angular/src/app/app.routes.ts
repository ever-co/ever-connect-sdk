import { Routes } from '@angular/router';
import { AuthGuard } from './auth.guard';
import { DashboardComponent } from './dashboard.component';
import { settingsRoutes } from './settings.routes';

declare const registry: { getRoutes(location: string): Routes };

const PLATFORM_PATH = 'ever-platform';

function dashboardRoutes(): Routes {
	return [{ path: 'dashboard', component: DashboardComponent }];
}

export const appRoutes: Routes = [
	{ path: '', redirectTo: 'pages', pathMatch: 'full' },
	{ path: 'auth', loadChildren: () => import('@fixture/lazy').then((m) => m.AuthModule) },
	{
		path: 'pages',
		canActivate: [AuthGuard],
		children: [
			...dashboardRoutes(),
			{ path: 'settings', children: settingsRoutes },
			{
				path: `integrations/${PLATFORM_PATH}`,
				loadComponent: () => import('./platform.component').then((m) => m.PlatformComponent)
			},
			{ path: 'employees/:id', loadChildren: () => import('./employees/employees.routes').then((m) => m.EMPLOYEE_ROUTES) },
			{ path: 'reports', loadChildren: () => import('./reports/reports.module').then((m) => m.ReportsModule) },
			// The same lazily loaded module under a second parent: its routes exist in both places.
			{ path: 'organizations/edit/:id', loadChildren: () => import('./reports/reports.module').then((m) => m.ReportsModule) },
			...registry.getRoutes('page-sections')
		]
	},
	{ path: '**', redirectTo: 'pages' }
];
