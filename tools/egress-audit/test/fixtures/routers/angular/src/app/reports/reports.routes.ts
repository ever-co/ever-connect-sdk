import { Routes } from '@angular/router';
import { AmountsComponent, TimeComponent } from './report.components';

export function buildReportRoutes(): Routes {
	const children: Routes = [
		{ path: 'time', component: TimeComponent },
		{ path: 'amounts', component: AmountsComponent },
		// A module that loads itself: walked once on each chain, then opened at its own path.
		{ path: 'nested', loadChildren: () => import('./reports.module').then((m) => m.ReportsModule) }
	];
	return [{ path: '', children }];
}
