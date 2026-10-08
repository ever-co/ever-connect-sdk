import { NgModule } from '@angular/core';
import { ROUTES, RouterModule } from '@angular/router';
import { buildReportRoutes } from './reports.routes';

@NgModule({
	imports: [RouterModule.forChild([])],
	providers: [{ provide: ROUTES, useFactory: () => buildReportRoutes(), multi: true }]
})
export class ReportsModule {}
